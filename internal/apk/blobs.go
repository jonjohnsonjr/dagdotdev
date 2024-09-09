package apk

import (
	"fmt"
	"io"
)

// Pretends to implement Seek because ServeContent only cares about checking
// for the size by calling Seek(0, io.SeekEnd)
type sizeSeeker struct {
	rc   io.Reader
	size int64
}

func (s *sizeSeeker) Seek(offset int64, whence int) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

func (s *sizeSeeker) Read(p []byte) (int, error) {
	return s.rc.Read(p)
}

func (s *sizeSeeker) Size() int64 {
	return s.size
}

type sizeBlob struct {
	io.ReadCloser
	size int64
}

func (s *sizeBlob) Size() int64 {
	return s.size
}
