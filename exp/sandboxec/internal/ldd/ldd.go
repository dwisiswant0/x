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
	"fmt"
	"os"
	"os/exec"
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
	Interp  string
	SONames []string
}

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
	n := len(line)
	i := 0

	nextToken := func() (string, bool) {
		for i < n {
			c := line[i]
			if c != ' ' && c != '\t' {
				break
			}
			i++
		}

		if i >= n {
			return "", false
		}

		start := i
		for i < n {
			c := line[i]
			if c == ' ' || c == '\t' {
				break
			}
			i++
		}

		return line[start:i], true
	}

	tok0, ok := nextToken()
	if !ok {
		return "", false
	}

	tok1, ok := nextToken()
	if !ok {
		return "", false
	}

	tok2, ok := nextToken()
	if !ok || len(tok2) == 0 {
		return "", false
	}

	if tok1 != "=>" {
		return "", false
	}

	if tok0 == tok2 {
		return "", false
	}

	// If the third part is a memory address instead
	// of a file system path, the entry should be skipped.
	// For example: linux-vdso.so.1 => (0x00007ffe4972d000)
	if tok2[0] == '(' {
		return "", false
	}

	return tok2, true
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

		depCacheFile = filepath.Join(cacheDir, "go.dw1.io", "x", "exp", "sandboxec", "ldd", "deps-v2.cache")
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
	builder.WriteString("v2|")
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

func followInternal(path string, seen map[string]struct{}) error {
	for {
		if _, ok := seen[path]; ok {
			return nil
		}
		i, err := os.Lstat(path)
		if err != nil {
			return err
		}

		seen[path] = struct{}{}
		if i.Mode().IsRegular() {
			return nil
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
						if cached.Interp != "" {
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

	// People expect to see the interps first.
	for s := range interps {
		libs = append(libs, s)
	}
	for s := range list {
		libs = append(libs, s)
	}
	return libs, nil
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
