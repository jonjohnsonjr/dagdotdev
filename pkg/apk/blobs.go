package apk

import (
	"fmt"
	"io"
	"net/http"
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
	rc   io.ReadCloser
	size int64

	n int64

	w http.ResponseWriter
	h *handler

	progress int
	total    int
}

func (s *sizeBlob) Read(p []byte) (int, error) {
	n, err := s.rc.Read(p)
	s.n += int64(n)

	if s.h != nil && s.w != nil {
		if next := int(float64(s.total) * (float64(s.n) / float64(s.size))); next > s.progress {
			fmt.Fprintf(s.w, "<span slot=\"progress\">.</span>\n")
			s.progress = next
			if flusher, ok := s.w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}
	return n, err
}

func (s *sizeBlob) Size() int64 {
	return s.size
}

func (s *sizeBlob) Close() error {
	return s.rc.Close()
}
