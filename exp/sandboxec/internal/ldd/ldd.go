// Copyright 2026 Dwi Siswanto.
// Licensed under the Apache License, Version 2.0.

// Copyright 2009-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license.

//go:build freebsd || linux

package ldd

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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
	Interp  string
	SONames []string
}

// librariesExist reports whether every library in a cached entry still exists.
// A library can move without ldconfig, such as one found through RUNPATH, so
// an entry that names a missing one is looked up again.
func librariesExist(paths []string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}

	return true
}

// ldSoCache is the loader cache, which ldconfig rewrites when libraries are
// added, removed, or moved, and ldSoPreload lists the libraries the loader
// preloads into every program.
var (
	ldSoCache   = "/etc/ld.so.cache"
	ldSoPreload = "/etc/ld.so.preload"
)

// func parseinterp(input string) ([]string, error) {
// 	scanner := bufio.NewScanner(strings.NewReader(input))
// 	scanner.Buffer(make([]byte, 1024), 1024*1024)

// 	return parseinterpScanner(scanner), nil
// }

func parseinterpScanner(scanner *bufio.Scanner) []string {
	names := make([]string, 0, 16)
	for scanner.Scan() {
		name, ok := parseinterpLine(scanner.Text())
		if !ok {
			continue
		}
		names = append(names, name)
	}

	return names
}

func parseinterpLine(line string) (string, bool) {
	// A loaded library reads "name => path (0xaddress)". The path runs to the
	// address, since it may contain spaces.
	name, path, ok := strings.Cut(strings.TrimSpace(line), " => ")
	if !ok {
		return "", false
	}
	if i := strings.LastIndex(path, " (0x"); i >= 0 {
		path = path[:i]
	}
	path = strings.TrimSpace(path)

	// Only an absolute path names a loaded file. Skip a memory address, as in
	// linux-vdso.so.1 => (0x00007ffe4972d000), and a missing library, as in
	// libfoo.so.1 => not found, whose "not" would read as a relative path.
	if !strings.HasPrefix(path, "/") || path == name {
		return "", false
	}

	return path, true
}

// runinterp runs the interpreter with the --list switch
// and the file as an argument. For each returned line
// it looks for => as the second field, indicating a
// real .so (as opposed to the .vdso or a string like
// 'not a dynamic executable'.
func runinterp(interp, file string) ([]string, error) {
	cmd := exec.Command(interp, "--list", file)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	names := make([]string, 0, 16)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	names = append(names, parseinterpScanner(scanner)...)

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return nil, err
	}

	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("%w: %s", ee, stderr.String())
		}
		return nil, err
	}

	return names, nil
}

func getDepCache() *fastcache.Cache[string, depCacheEntry] {
	depCacheOnce.Do(func() {
		cacheDir, err := os.UserCacheDir()
		if err != nil || cacheDir == "" {
			depCache = fastcache.New[string, depCacheEntry](16_384)
			return
		}

		depCacheFile = filepath.Join(cacheDir, "go.dw1.io", "x", "exp", "sandboxec", "ldd", "deps.cache")
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

	// Which libraries the loader picks also depends on its cache, its preload
	// list and its environment, so an entry from before any of them changed is
	// stale.
	for _, path := range []string{ldSoCache, ldSoPreload} {
		builder.WriteByte('|')
		if info, err := os.Stat(path); err == nil {
			builder.WriteString(strconv.FormatInt(info.Size(), 10))
			builder.WriteByte('|')
			builder.WriteString(strconv.FormatInt(info.ModTime().UnixNano(), 10))
		}
	}
	for _, name := range []string{"LD_LIBRARY_PATH", "LD_PRELOAD", "GLIBC_TUNABLES"} {
		builder.WriteByte(0)
		builder.WriteString(os.Getenv(name))
	}

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

func GetInterp(file string) (string, error) {
	r, err := os.Open(file)
	if err != nil {
		return "fail", err
	}
	defer func() {
		_ = r.Close()
	}()

	f, err := elf.NewFile(r)
	if err != nil {
		return "", nil
	}

	s := f.Section(".interp")
	var interp string
	if s != nil {
		// If there is an interpreter section, it should be
		// an error if we can't read it.
		i, err := s.Data()
		if err != nil {
			return "fail", err
		}

		// .interp section is file name + \0 character.
		interp := strings.TrimRight(string(i), "\000")

		// Ignore #! interpreters
		if strings.HasPrefix(interp, "#!") {
			return "", nil
		}
		return interp, nil
	}

	if interp == "" {
		if f.Type != elf.ET_DYN || f.Class == elf.ELFCLASSNONE {
			return "", nil
		}
		bit64 := true
		if f.Class != elf.ELFCLASS64 {
			bit64 = false
		}

		// This is a shared library. Turns out you can run an
		// interpreter with --list and this shared library as an
		// argument. What interpreter do we use? Well, there's no way to
		// know. You have to guess.  I'm not sure why they could not
		// just put an interp section in .so's but maybe that would
		// cause trouble somewhere else.
		interp, err = LdSo(bit64)
		if err != nil {
			return "fail", err
		}
	}
	return interp, nil
}

// follow returns all paths and any files they recursively point to through
// symlinks.
//
// A path or link target that does not exist ends that chain without error, so
// a stale library entry does not abort the whole batch. So does a chain that
// loops or has more links than the kernel follows. The links of such a chain
// are dropped too, since the path they were followed from cannot be opened,
// and so is any link that does not open to the file that path opens to.
func follow(paths ...string) ([]string, error) {
	seen := make(map[string]struct{})

	for _, path := range paths {
		if err := followInternal(path, seen); err != nil {
			return nil, err
		}
	}

	deps := make([]string, 0, len(seen))
	for s := range seen {
		deps = append(deps, s)
	}
	return deps, nil
}

// maxSymlinks is the most symlinks the kernel follows when opening a path, its
// MAXSYMLINKS. One more, or a loop, fails with ELOOP.
const maxSymlinks = 40

func followInternal(path string, seen map[string]struct{}) error {
	start := path
	var added []string
	drop := func() error {
		for _, link := range added {
			delete(seen, link)
		}
		return nil
	}
	// keep keeps the paths of the chain that open to the file start opens to.
	// The kernel also counts symlinks in directory components, and in the part
	// of the chain that an earlier path already followed, and it applies ".."
	// in a link's target to the link's resolved directory. This walk sees none
	// of that.
	keep := func() error {
		target, err := os.Stat(start)
		if err != nil {
			return drop()
		}
		for _, link := range added {
			if info, err := os.Stat(link); err != nil || !os.SameFile(info, target) {
				delete(seen, link)
			}
		}
		return nil
	}

	for {
		if _, ok := seen[path]; ok {
			if slices.Contains(added, path) {
				return drop()
			}
			return keep()
		}
		i, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return drop()
		}
		if err != nil {
			return err
		}

		seen[path] = struct{}{}
		added = append(added, path)
		if i.Mode().IsRegular() {
			return keep()
		}
		if len(added) > maxSymlinks {
			return drop()
		}

		// If it's a symlink, read works; if not, it fails.
		// We can skip testing the type, since we still have to
		// handle any error if it's a link.
		next, err := os.Readlink(path)
		if err != nil {
			return err
		}

		// A relative link has to be interpreted relative to the file's
		// parent's path.
		if !filepath.IsAbs(next) {
			next = filepath.Join(filepath.Dir(path), next)
		}
		path = next
	}
}

// List returns a list of all library dependencies for a set of files.
//
// If a file has no dependencies, that is not an error. Per-file failures are
// skipped so one problematic file does not abort processing the whole batch.
// A path is returned only if it is a library, whatever the loader reports.
//
// It's not an error for a file to not be an ELF.
func List(names ...string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}

	cache := getDepCache()

	workerCount := min(min(max(runtime.GOMAXPROCS(0), 1), 8), len(names))

	type listResult struct {
		interp  string
		sonames []string
	}

	jobs := make(chan string)
	results := make(chan listResult, workerCount)

	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range jobs {
				cacheKey := ""
				if key, ok := depCacheKey(n); ok {
					cacheKey = key
					if cached, found := cache.Get(cacheKey); found {
						if cached.Interp != "" && librariesExist(cached.SONames) {
							results <- listResult{interp: cached.Interp, sonames: cached.SONames}
							continue
						}
					}
				}

				interp, err := GetInterp(n)
				if err != nil || interp == "" {
					continue
				}

				// Run the interpreter to get dependencies.
				sonames, err := runinterp(interp, n)
				if err != nil {
					continue
				}

				if cacheKey != "" {
					cache.Set(cacheKey, depCacheEntry{Interp: interp, SONames: sonames})
					maybeSaveDepCache()
				}

				results <- listResult{interp: interp, sonames: sonames}
			}
		}()
	}

	go func() {
		for _, n := range names {
			jobs <- n
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	list := make(map[string]struct{})
	interps := make(map[string]struct{})
	for res := range results {
		interps[res.interp] = struct{}{}
		for _, name := range res.sonames {
			list[name] = struct{}{}
		}
	}

	libs := make([]string, 0, len(list)+len(interps))

	// The interpreter and the loader's report come from the files being
	// inspected: the loader prints the names and search paths they store as
	// they are, so a line can name any path. Keep only the paths that are
	// libraries.
	//
	// People expect to see the interps first.
	for s := range interps {
		if isLibrary(s) {
			libs = append(libs, s)
		}
	}
	for s := range list {
		if isLibrary(s) {
			libs = append(libs, s)
		}
	}
	return libs, nil
}

// isLibrary reports whether path opens as a file the loader would map as a
// library: an ELF shared object that is not a position-independent executable.
func isLibrary(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer func() {
		_ = f.Close()
	}()

	if f.Type != elf.ET_DYN {
		return false
	}
	flags, err := f.DynValue(elf.DT_FLAGS_1)
	if err != nil {
		return false
	}
	for _, flag := range flags {
		if elf.DynFlag1(flag)&elf.DF_1_PIE != 0 {
			return false
		}
	}

	return true
}

// FList returns a list of all library dependencies for a set of files,
// including following symlinks.
//
// If a file has no dependencies, that is not an error. Per-file failures are
// skipped so one problematic file does not abort processing the whole batch.
//
// It's not an error for a file to not be an ELF.
func FList(names ...string) ([]string, error) {
	deps, err := List(names...)
	if err != nil {
		return nil, err
	}
	return follow(deps...)
}
