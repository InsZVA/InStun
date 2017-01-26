package instun

import (
	"io"
	"errors"
	"bytes"
	"encoding/binary"
)

var (
	ERROR_WRITE_OUT_OF_BOUND = errors.New("StunReader: write out of bound")
)

type ReaderAtWriterTo interface {
	io.ReaderAt
	io.WriterTo
}

// NewStunReader returns a StunReader that reads from r
// starting at offset off and stops with EOF after n bytes.
func NewStunReader(r ReaderAtWriterTo, off int64, n int64) *StunReader {
	return &StunReader{r, off, off, off + n}
}

// NewStunReaderFromBytes returns a StunReader that reads from a
// bytes at start and stops with EOF after len(bytes)
func NewStunReaderFromBytes(b []byte) *StunReader {
	return NewStunReader(bytes.NewReader(b), 0, int64(len(b)))
}

// StunReader is just like io.SectionReader
// But io.SectionReader unexpectedly not implements
// Left() to return the left size
type StunReader struct {
	r ReaderAtWriterTo
	base  int64
	off   int64
	limit int64
}

// Copy from io.SectionReader
func (reader *StunReader) Read(p []byte) (n int, err error) {
	if reader.off >= reader.limit {
		return 0, io.EOF
	}
	if max := reader.limit - reader.off; int64(len(p)) > max {
		p = p[0:max]
	}
	n, err = reader.r.ReadAt(p, reader.off)
	reader.off += int64(n)
	return
}

var errWhence = errors.New("Seek: invalid whence")
var errOffset = errors.New("Seek: invalid offset")

// Copy from io.SectionReader
func (reader *StunReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	default:
		return 0, errWhence
	case io.SeekStart:
		offset += reader.base
	case io.SeekCurrent:
		offset += reader.off
	case io.SeekEnd:
		offset += reader.limit
	}
	if offset < reader.base {
		return 0, errOffset
	}
	reader.off = offset
	return offset - reader.base, nil
}

// Copy from io.SectionReader
func (reader *StunReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 || off >= reader.limit-reader.base {
		return 0, io.EOF
	}
	off += reader.base
	if max := reader.limit - off; int64(len(p)) > max {
		p = p[0:max]
		n, err = reader.r.ReadAt(p, off)
		if err == nil {
			err = io.EOF
		}
		return n, err
	}
	return reader.r.ReadAt(p, off)
}

// Copy from io.SectionReader
// Size returns the size of the section in bytes.
func (reader *StunReader) Size() int64 { return reader.limit - reader.base }

func (reader *StunReader) Left() int64 {
	return reader.limit - reader.off
}

func (reader *StunReader) BigEndianRead(v interface{}) error {
	return binary.Read(reader, binary.BigEndian, v)
}

func (reader *StunReader) LittleEndianRead(v interface{}) error {
	return binary.Read(reader, binary.LittleEndian, v)
}

func (reader *StunReader) Reset() {
	reader.off = reader.base
}

func (reader *StunReader) Next(n int) {
	reader.off += int64(n)
}

func (reader *StunReader) WriteTo(w io.Writer) (int64 ,error) {
	return reader.r.WriteTo(w)
}