package file

import (
	"io"
	"os"

	"go.dw1.io/mmapfile"
)

var (
	_ io.Reader       = (*File)(nil)
	_ io.Writer       = (*File)(nil)
	_ io.Seeker       = (*File)(nil)
	_ io.ReaderAt     = (*File)(nil)
	_ io.WriterAt     = (*File)(nil)
	_ io.Closer       = (*File)(nil)
	_ io.ReaderFrom   = (*File)(nil)
	_ io.WriterTo     = (*File)(nil)
	_ io.StringWriter = (*File)(nil)
)

// File wraps either a memory-mapped file (preferred) or a plain os.File when
// mmap is unavailable on the current platform.
type File struct {
	mm *mmapfile.MmapFile
	os *os.File
}

// Open maps the file into memory when supported; otherwise it falls back to
// os.Open. No size hint is needed because the existing file size is used. If
// mmap setup fails for any reason (including platform constraints), the
// os.File path is returned instead.
func Open(name string) (*File, error) {
	mf, err := mmapfile.Open(name)
	if err == nil {
		return &File{mm: mf}, nil
	}

	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	return &File{os: f}, nil
}

// OpenFile maps the file into memory when supported; otherwise it falls back
// to os.OpenFile. mmapfile does not support O_APPEND and requires size>0 when
// creating or truncating; those cases automatically use the os.File fallback.
//
// When falling back and size>0 with create/truncate flags, the file is
// explicitly truncated to the requested size to mirror the mmap path.
func OpenFile(name string, flag int, perm os.FileMode, size int64) (*File, error) {
	if canMmap(flag, size) {
		if mf, err := mmapfile.OpenFile(name, flag, perm, size); err == nil {
			return &File{mm: mf}, nil
		}
	}

	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}

	if size > 0 && (flag&(os.O_CREATE|os.O_TRUNC) != 0) {
		if err := f.Truncate(size); err != nil {
			f.Close()
			return nil, err
		}
	}

	return &File{os: f}, nil
}

func (f *File) Read(p []byte) (int, error) {
	if f.mm != nil {
		return f.mm.Read(p)
	}

	return f.os.Read(p)
}

// Write writes len(p) bytes, advancing the current offset.
func (f *File) Write(p []byte) (int, error) {
	if f.mm != nil {
		return f.mm.Write(p)
	}

	return f.os.Write(p)
}

// Seek sets the next read/write offset.
func (f *File) Seek(offset int64, whence int) (int64, error) {
	if f.mm != nil {
		return f.mm.Seek(offset, whence)
	}

	return f.os.Seek(offset, whence)
}

// ReadAt reads starting at absolute offset without moving the current offset.
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if f.mm != nil {
		return f.mm.ReadAt(p, off)
	}

	return f.os.ReadAt(p, off)
}

// WriteAt writes starting at absolute offset without moving the current offset.
func (f *File) WriteAt(p []byte, off int64) (int, error) {
	if f.mm != nil {
		return f.mm.WriteAt(p, off)
	}

	return f.os.WriteAt(p, off)
}

// Close releases resources held by the file.
func (f *File) Close() error {
	if f.mm != nil {
		return f.mm.Close()
	}

	return f.os.Close()
}

// ReadFrom streams data from r into the file until EOF.
func (f *File) ReadFrom(r io.Reader) (int64, error) {
	if f.mm != nil {
		return f.mm.ReadFrom(r)
	}

	return f.os.ReadFrom(r)
}

// WriteTo writes the file contents to w.
func (f *File) WriteTo(w io.Writer) (int64, error) {
	if f.mm != nil {
		return f.mm.WriteTo(w)
	}

	return f.os.WriteTo(w)
}

// WriteString writes the contents of s, advancing the current offset.
func (f *File) WriteString(s string) (int, error) {
	if f.mm != nil {
		return f.mm.WriteString(s)
	}

	return f.os.WriteString(s)
}

// Bytes exposes the mmap'd region when available; nil is returned for the
// os.File fallback because zero-copy access is unavailable there.
func (f *File) Bytes() []byte {
	if f.mm != nil {
		return f.mm.Bytes()
	}

	return nil
}

// Len returns the mapped length, or the file size for the os.File fallback.
func (f *File) Len() int {
	if f.mm != nil {
		return f.mm.Len()
	}

	info, err := f.os.Stat()
	if err != nil {
		return 0
	}

	return int(info.Size())
}

// Name returns the original file name.
func (f *File) Name() string {
	if f.mm != nil {
		return f.mm.Name()
	}

	return f.os.Name()
}

// Stat retrieves file information.
func (f *File) Stat() (os.FileInfo, error) {
	if f.mm != nil {
		return f.mm.Stat()
	}

	return f.os.Stat()
}

// Sync flushes data to disk.
func (f *File) Sync() error {
	if f.mm != nil {
		return f.mm.Sync()
	}

	return f.os.Sync()
}

func canMmap(flag int, size int64) bool {
	if flag&os.O_APPEND != 0 {
		return false
	}

	if flag&(os.O_CREATE|os.O_TRUNC) != 0 && size <= 0 {
		return false
	}

	return true
}
