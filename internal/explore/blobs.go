package explore

import (
	"bufio"
	"bytes"
	ogzip "compress/gzip"
	"fmt"
	"io"
	"log"

	"github.com/jonjohnsonjr/dag.dev/internal/gzip"
	"github.com/jonjohnsonjr/dag.dev/internal/zstd"
)

// Pretends to implement Seek because ServeContent only cares about checking
// for the size by calling Seek(0, io.SeekEnd)
type sizeSeeker struct {
	rc     io.Reader
	size   int64
	debug  string
	buf    *bufio.Reader
	seeked bool
}

func (s *sizeSeeker) Seek(offset int64, whence int) (int64, error) {
	if debug {
		log.Printf("sizeSeeker.Seek(%d, %d)", offset, whence)
	}
	s.seeked = true
	if offset == 0 && whence == io.SeekEnd {
		return s.size, nil
	}
	if offset == 0 && whence == io.SeekStart {
		return 0, nil
	}

	return 0, fmt.Errorf("ServeContent(%q): Seek(%d, %d)", s.debug, offset, whence)
}

func (s *sizeSeeker) Read(p []byte) (int, error) {
	if debug {
		log.Printf("sizeSeeker.Read(%d)", len(p))
	}
	// Handle first read.
	if s.buf == nil {
		if debug {
			log.Println("first read")
		}
		if len(p) <= bufferLen {
			s.buf = bufio.NewReaderSize(s.rc, bufferLen)
		} else {
			s.buf = bufio.NewReaderSize(s.rc, len(p))
		}

		// Currently, http will sniff before it seeks for size. If we haven't seen
		// a Read() but have seen a Seek already, that means we shouldn't peek.
		if !s.seeked {
			// Peek to handle the first content sniff.
			b, err := s.buf.Peek(len(p))
			if err != nil {
				if err == io.EOF {
					n, _ := bytes.NewReader(b).Read(p)
					return n, io.EOF
				} else {
					return 0, err
				}
			}
			return bytes.NewReader(b).Read(p)
		}
	}

	// TODO: We assume they will always sniff then reset.
	n, err := s.buf.Read(p)
	if debug {
		log.Printf("sizeSeeker.Read(%d): (%d, %v)", len(p), n, err)
	}
	return n, err
}

type sizeBlob struct {
	io.ReadCloser
	size int64
}

func (s *sizeBlob) Size() int64 {
	return s.size
}

const (
	magicGNU, versionGNU     = "ustar ", " \x00"
	magicUSTAR, versionUSTAR = "ustar\x00", "00"
)

func tarPeek(r io.Reader) (bool, gzip.PeekReader, error) {
	// Make sure it's more than 512
	var pr gzip.PeekReader
	if p, ok := r.(gzip.PeekReader); ok {
		pr = p
	} else {
		// For tar peek.
		pr = bufio.NewReaderSize(r, 1<<16)
	}

	block, err := pr.Peek(512)
	if err != nil {
		// https://github.com/google/go-containerregistry/issues/367
		if err == io.EOF {
			return false, pr, nil
		}
		return false, pr, err
	}

	magic := string(block[257:][:6])
	isTar := magic == magicGNU || magic == magicUSTAR
	return isTar, pr, nil
}

func gztarPeek(r io.Reader) (bool, gzip.PeekReader, error) {
	pr := bufio.NewReaderSize(r, 1<<16)

	// Should be enough to read first block?
	zb, err := pr.Peek(1024)
	if err != nil {
		if err != io.EOF {
			return false, pr, err
		}
	}

	br := bytes.NewReader(zb)
	ok, zpr, err := gzip.Peek(br)
	if !ok {
		return ok, pr, err
	}

	zr, err := ogzip.NewReader(zpr)
	if err != nil {
		return false, pr, err
	}
	ok, _, err = tarPeek(zr)
	return ok, pr, err
}

func zstdTarPeek(r io.Reader) (bool, gzip.PeekReader, error) {
	pr := bufio.NewReaderSize(r, 1<<16)

	// Should be enough to read first block?
	zb, err := pr.Peek(1024)
	if err != nil {
		if err != io.EOF {
			return false, pr, err
		}
	}

	br := bytes.NewReader(zb)
	ok, zpr, err := zstdPeek(br)
	if !ok {
		return ok, pr, err
	}

	zr, err := ogzip.NewReader(zpr)
	if err != nil {
		return false, pr, err
	}
	ok, _, err = tarPeek(zr)
	return ok, pr, err
}

func zstdPeek(r io.Reader) (bool, gzip.PeekReader, error) {
	// Make sure it's more than 512
	var pr gzip.PeekReader
	if p, ok := r.(gzip.PeekReader); ok {
		pr = p
	} else {
		// For tar peek.
		pr = bufio.NewReaderSize(r, 1<<16)
	}

	return checkHeader(pr, zstd.MagicHeader)
}

// CheckHeader checks whether the first bytes from a PeekReader match an expected header
func checkHeader(pr gzip.PeekReader, expectedHeader []byte) (bool, gzip.PeekReader, error) {
	header, err := pr.Peek(len(expectedHeader))
	if err != nil {
		// https://github.com/google/go-containerregistry/issues/367
		if err == io.EOF {
			return false, pr, nil
		}
		return false, pr, err
	}
	return bytes.Equal(header, expectedHeader), pr, nil
}
