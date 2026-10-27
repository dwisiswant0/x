//go:build darwin
// +build darwin

package macho

import (
	"debug/macho"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.dw1.io/fastcache"
)

var (
	depCacheOnce sync.Once
	depCache     *fastcache.Cache[string, depCacheEntry]
	depCacheFile string

	depCacheSaveMu     sync.Mutex
	depCacheLastSaveAt time.Time
	depCacheWrites     int
)

type depCacheEntry struct {
	Deps []string
}

func GetDependencies(root string) ([]string, error) {
	if root == "" {
		return nil, nil
	}

	cache := getDepCache()
	if key, ok := depCacheKey(root); ok {
		if cached, found := cache.Get(key); found {
			return append([]string(nil), cached.Deps...), nil
		}

		deps, complete := getDeps(root)
		if complete {
			cache.Set(key, depCacheEntry{Deps: deps})
			maybeSaveDepCache()
		}

		return append([]string(nil), deps...), nil
	}

	deps, _ := getDeps(root)

	return deps, nil
}

// getDeps returns the dependencies of root and, recursively, of each dylib,
// and whether it read every file it reached.
//
// A file that is not Mach-O or cannot be read contributes no dependencies.
// Per-file failures are skipped so one problematic file does not abort
// processing the whole walk. Only a root that is not Mach-O, such as a script,
// leaves the result complete: other failures can be transient, such as a
// permission change or a dylib being replaced, so their result is not cached.
func getDeps(root string) ([]string, bool) {
	rootPath := filepath.Clean(root)
	execDir := filepath.Dir(rootPath)

	deps := make([]string, 0)
	seenDeps := make(map[string]struct{})
	visited := make(map[string]struct{})
	complete := true

	var walk func(path string, cpu macho.Cpu)
	walk = func(path string, cpu macho.Cpu) {
		cleaned := filepath.Clean(path)
		if _, ok := visited[cleaned]; ok {
			return
		}
		visited[cleaned] = struct{}{}

		libraries, rpaths, libCPU, err := readMachO(cleaned, cpu)
		if err != nil {
			if cleaned != rootPath || !notMachO(cleaned) {
				complete = false
			}

			return
		}

		for _, lib := range libraries {
			resolved := resolveLibraryPath(lib, cleaned, execDir, rpaths)
			if resolved == "" {
				continue
			}

			info, statErr := os.Stat(resolved)
			if statErr != nil || info.IsDir() {
				continue
			}

			deps = appendUniqWithSeen(deps, seenDeps, resolved)
			walk(resolved, libCPU)
		}
	}

	walk(rootPath, hostCPU())

	return deps, complete
}

// notMachO reports whether the file at path is certainly not Mach-O: it is
// shorter than a magic number, or starts with one that is not Mach-O. A read
// error is not certain, since it can be transient.
func notMachO(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() {
		_ = f.Close()
	}()

	var magic [4]byte
	if n, err := io.ReadFull(f, magic[:]); n < len(magic) {
		return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
	}

	switch binary.BigEndian.Uint32(magic[:]) {
	case macho.MagicFat, macho.Magic32, macho.Magic64, 0xcefaedfe, 0xcffaedfe:
		return false
	}

	return true
}

// hostCPU returns the CPU of the images a native process loads, or 0 when
// the architecture has no Mach-O CPU type here.
func hostCPU() macho.Cpu {
	switch runtime.GOARCH {
	case "amd64":
		return macho.CpuAmd64
	case "arm64":
		return macho.CpuArm64
	}

	return 0
}

// readMachO returns the imported libraries and rpaths of the Mach-O file at
// path, read through its images for cpu, and the CPU its own dylibs load as.
// A cpu of 0 reads every image of a universal binary.
func readMachO(path string, cpu macho.Cpu) (libraries, rpaths []string, libCPU macho.Cpu, err error) {
	files, libCPU, closeFn, err := openMachO(path, cpu)
	if err != nil {
		return nil, nil, 0, err
	}
	defer closeFn()

	for _, mf := range files {
		libs, err := mf.ImportedLibraries()
		if err != nil {
			return nil, nil, 0, err
		}
		libraries = append(libraries, libs...)

		for _, load := range mf.Loads {
			rpath, ok := load.(*macho.Rpath)
			if !ok || rpath.Path == "" {
				continue
			}
			rpaths = append(rpaths, rpath.Path)
		}
	}

	return libraries, rpaths, libCPU, nil
}

// openMachO opens a thin or universal Mach-O file and returns the images to
// inspect for cpu, the CPU its dylibs load as, and a function that closes the
// file.
//
// Most system binaries are universal, which [macho.Open] rejects. A process
// loads only the slice for its CPU, and its dylibs load as that CPU too, which
// for a thin x86_64 binary under Rosetta is not the host's. If no slice
// matches, every slice is used rather than none, and so are the dylibs' slices.
func openMachO(path string, cpu macho.Cpu) ([]*macho.File, macho.Cpu, func(), error) {
	ff, err := macho.OpenFat(path)
	if errors.Is(err, macho.ErrNotFat) {
		mf, err := macho.Open(path)
		if err != nil {
			return nil, 0, nil, err
		}

		return []*macho.File{mf}, mf.Cpu, func() { _ = mf.Close() }, nil
	}
	if err != nil {
		return nil, 0, nil, err
	}

	files := make([]*macho.File, 0, len(ff.Arches))
	for i := range ff.Arches {
		if ff.Arches[i].Cpu == cpu {
			files = append(files, ff.Arches[i].File)
		}
	}
	if len(files) == 0 {
		cpu = 0
		for i := range ff.Arches {
			files = append(files, ff.Arches[i].File)
		}
	}

	return files, cpu, func() { _ = ff.Close() }, nil
}

func getDepCache() *fastcache.Cache[string, depCacheEntry] {
	depCacheOnce.Do(func() {
		cacheDir, err := os.UserCacheDir()
		if err != nil || cacheDir == "" {
			depCache = fastcache.New[string, depCacheEntry](16_384)
			return
		}

		depCacheFile = filepath.Join(cacheDir, "go.dw1.io", "x", "exp", "sandboxec", "macho", "deps.cache")
		if err := os.MkdirAll(filepath.Dir(depCacheFile), 0o755); err != nil {
			depCache = fastcache.New[string, depCacheEntry](16_384)
			depCacheFile = ""
			return
		}

		depCache = fastcache.LoadFromFileOrNew[string, depCacheEntry](depCacheFile, 16_384)
	})

	return depCache
}

func depCacheKey(file string) (string, bool) {
	if file == "" {
		return "", false
	}

	info, err := os.Stat(file)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}

	var builder strings.Builder
	builder.Grow(len(file) + 56)
	builder.WriteString(file)
	builder.WriteByte('|')
	builder.WriteString(strconv.FormatInt(info.Size(), 10))
	builder.WriteByte('|')
	builder.WriteString(strconv.FormatInt(info.ModTime().UnixNano(), 10))

	return builder.String(), true
}

func maybeSaveDepCache() {
	if depCacheFile == "" || depCache == nil {
		return
	}

	depCacheSaveMu.Lock()
	defer depCacheSaveMu.Unlock()

	depCacheWrites++
	if depCacheWrites < 32 && time.Since(depCacheLastSaveAt) < 2*time.Second {
		return
	}

	if err := depCache.SaveToFile(depCacheFile); err == nil {
		depCacheWrites = 0
		depCacheLastSaveAt = time.Now()
	}
}

func resolveLibraryPath(lib, loaderPath, execDir string, rpaths []string) string {
	if strings.HasPrefix(lib, "/") {
		return filepath.Clean(lib)
	}

	loaderDir := filepath.Dir(loaderPath)

	if strings.HasPrefix(lib, "@loader_path/") {
		suffix := strings.TrimPrefix(lib, "@loader_path/")
		return filepath.Clean(filepath.Join(loaderDir, suffix))
	}

	if strings.HasPrefix(lib, "@executable_path/") {
		suffix := strings.TrimPrefix(lib, "@executable_path/")
		return filepath.Clean(filepath.Join(execDir, suffix))
	}

	if strings.HasPrefix(lib, "@rpath/") {
		suffix := strings.TrimPrefix(lib, "@rpath/")
		for _, rp := range rpaths {
			resolvedRPath := resolveRPath(rp, loaderDir, execDir)
			if resolvedRPath == "" {
				continue
			}

			candidate := filepath.Clean(filepath.Join(resolvedRPath, suffix))
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate
			}
		}
	}

	if !strings.HasPrefix(lib, "@") {
		return filepath.Clean(filepath.Join(loaderDir, lib))
	}

	return ""
}

func resolveRPath(rpath, loaderDir, execDir string) string {
	if rpath == "" {
		return ""
	}

	if strings.HasPrefix(rpath, "/") {
		return filepath.Clean(rpath)
	}

	if strings.HasPrefix(rpath, "@loader_path/") {
		suffix := strings.TrimPrefix(rpath, "@loader_path/")
		return filepath.Clean(filepath.Join(loaderDir, suffix))
	}

	if strings.HasPrefix(rpath, "@executable_path/") {
		suffix := strings.TrimPrefix(rpath, "@executable_path/")
		return filepath.Clean(filepath.Join(execDir, suffix))
	}

	if !strings.HasPrefix(rpath, "@") {
		return filepath.Clean(filepath.Join(loaderDir, rpath))
	}

	return ""
}

func appendUniqWithSeen(dst []string, seen map[string]struct{}, values ...string) []string {
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		dst = append(dst, value)
	}
	return dst
}
