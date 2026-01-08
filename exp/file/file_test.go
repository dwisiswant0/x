package file

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenFileMmapPreferred(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")

	f, err := OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644, 4)
	if err != nil {
		t.Fatalf("OpenFile mmap: %v", err)
	}
	t.Cleanup(func() { f.Close() })

	if f.mm == nil {
		t.Skip("mmap backend unavailable; running fallback")
	}
	if f.os != nil {
		t.Fatalf("expected os backend to be nil when mmap is used")
	}

	if n, err := f.Write([]byte("hey")); err != nil || n != 3 {
		t.Fatalf("write mmap: n=%d err=%v", n, err)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek mmap: %v", err)
	}

	buf := make([]byte, 3)
	if n, err := f.Read(buf); err != nil || n != 3 || string(buf) != "hey" {
		t.Fatalf("read mmap: n=%d err=%v buf=%q", n, err, buf)
	}

	if got := f.Len(); got != 4 {
		t.Fatalf("len mmap: got %d want 4", got)
	}

	if f.Bytes() == nil {
		t.Fatalf("bytes mmap: expected non-nil slice")
	}
}

func TestOpenMmapPreferredExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "open.bin")

	content := []byte("xyz")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	f, err := Open(path)
	if err != nil {
		t.Fatalf("Open mmap: %v", err)
	}
	t.Cleanup(func() { f.Close() })

	if f.mm == nil {
		t.Skip("mmap backend unavailable; running fallback")
	}
	if f.os != nil {
		t.Fatalf("expected os backend to be nil when mmap is used")
	}

	buf := make([]byte, 3)
	if n, err := f.Read(buf); err != nil || n != 3 || string(buf) != "xyz" {
		t.Fatalf("read mmap open: n=%d err=%v buf=%q", n, err, buf)
	}

	if got := f.Len(); got != len(content) {
		t.Fatalf("len mmap open: got %d want %d", got, len(content))
	}

	if data := f.Bytes(); data == nil || string(data) != string(content) {
		t.Fatalf("bytes mmap open: got %q want %q", data, content)
	}
}

func TestOpenFileFallbackAppend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "append.txt")

	f, err := OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644, 0)
	if err != nil {
		t.Fatalf("OpenFile append fallback: %v", err)
	}
	t.Cleanup(func() { f.Close() })

	if f.mm != nil {
		t.Fatalf("expected mmap backend to be nil for append mode")
	}
	if f.os == nil {
		t.Fatalf("expected os backend for append mode fallback")
	}

	if n, err := f.Write([]byte("abc")); err != nil || n != 3 {
		t.Fatalf("write append: n=%d err=%v", n, err)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek append: %v", err)
	}

	buf := make([]byte, 3)
	if n, err := f.Read(buf); err != nil || n != 3 || string(buf) != "abc" {
		t.Fatalf("read append: n=%d err=%v buf=%q", n, err, buf)
	}

	if got := f.Len(); got != 3 {
		t.Fatalf("len append: got %d want 3", got)
	}

	if f.Bytes() != nil {
		t.Fatalf("bytes append: expected nil for os fallback")
	}
}

func TestOpenFileFallbackMissingSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nosize.txt")

	f, err := OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644, 0)
	if err != nil {
		t.Fatalf("OpenFile nosize fallback: %v", err)
	}
	t.Cleanup(func() { f.Close() })

	if f.mm != nil {
		t.Fatalf("expected mmap backend to be nil when size is missing")
	}
	if f.os == nil {
		t.Fatalf("expected os backend when size is missing")
	}

	if n, err := f.Write([]byte("hi")); err != nil || n != 2 {
		t.Fatalf("write nosize: n=%d err=%v", n, err)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek nosize: %v", err)
	}

	buf := make([]byte, 2)
	if n, err := f.Read(buf); err != nil || n != 2 || string(buf) != "hi" {
		t.Fatalf("read nosize: n=%d err=%v buf=%q", n, err, buf)
	}

	if got := f.Len(); got != 2 {
		t.Fatalf("len nosize: got %d want 2", got)
	}

	if f.Bytes() != nil {
		t.Fatalf("bytes nosize: expected nil for os fallback")
	}
}
