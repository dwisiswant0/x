// Package file provides an [os.File]-compatible API that prefers memory-mapped
// I/O via [mmapfile], automatically falling back to [os.File] when mmap is
// unavailable or unsuitable (e.g. append mode or missing size on create/trunc).
//
// The exported [File] type implements the common io interfaces (Reader, Writer,
// Seeker, ReaderAt, WriterAt, ReaderFrom, WriterTo, StringWriter, Closer).
// Use Open/OpenFile just like the standard library; if mmap is used, Bytes() gives
// zero-copy access to the mapped region and Len reports the mapped length.
// When mmap is not used, Bytes returns nil and Len reports the underlying file
// size via Stat.
//
// Limitations inherited from [mmapfile]:
//   - Files are fixed size after opening; no growth or truncate in place.
//   - [os.O_APPEND] is unsupported for mmap and always uses the [os.File] fallback.
//   - Creating or truncating with mmap requires a positive size.
//   - Cursor-based Read/Write share a single offset; prefer ReadAt/WriteAt for
//     concurrent or positional I/O.
package file
