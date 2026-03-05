//go:build darwin
// +build darwin

package macho

import (
	"debug/macho"
	"os"
	"path/filepath"
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

		deps, err := getDeps(root)
		if err != nil {
			return nil, err
		}

		cache.Set(key, depCacheEntry{Deps: deps})
		maybeSaveDepCache()

		return append([]string(nil), deps...), nil
	}

	return getDeps(root)
}

func getDeps(root string) ([]string, error) {
	rootPath := filepath.Clean(root)
	execDir := filepath.Dir(rootPath)

	deps := make([]string, 0)
	seenDeps := make(map[string]struct{})
	visited := make(map[string]struct{})

	var walk func(path string) error
	walk = func(path string) error {
		cleaned := filepath.Clean(path)
		if _, ok := visited[cleaned]; ok {
			return nil
		}
		visited[cleaned] = struct{}{}

		mf, err := macho.Open(cleaned)
		if err != nil {
			return err
		}
		defer func() {
			_ = mf.Close()
		}()

		libraries, err := mf.ImportedLibraries()
		if err != nil {
			return err
		}

		rpaths := make([]string, 0)
		for _, load := range mf.Loads {
			rpath, ok := load.(*macho.Rpath)
			if !ok || rpath.Path == "" {
				continue
			}
			rpaths = append(rpaths, rpath.Path)
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
			if err := walk(resolved); err != nil {
				return err
			}
		}

		return nil
	}

	if err := walk(rootPath); err != nil {
		return nil, err
	}

	return deps, nil
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
