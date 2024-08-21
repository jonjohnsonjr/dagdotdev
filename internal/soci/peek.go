package soci

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"

	ogzip "compress/gzip"

	kzstd "github.com/klauspost/compress/zstd"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/jonjohnsonjr/dagdotdev/internal/and"
	"github.com/jonjohnsonjr/dagdotdev/internal/gzip"
	"github.com/jonjohnsonjr/dagdotdev/internal/zstd"
)

const (
	magicGNU, versionGNU     = "ustar ", " \x00"
	magicUSTAR, versionUSTAR = "ustar\x00", "00"
)

type PeekReader interface {
	io.Reader
	Peek(n int) ([]byte, error)
}

// Peek detects streams of:
// tar
// tar+gzip
// tar+zstd
// gzip
// zstd
func Peek(rc io.ReadCloser) (string, io.ReadCloser, io.ReadCloser, error) {
	logs.Debug.Printf("Peek")
	buf := bufio.NewReaderSize(rc, 1<<16)
	pr := &and.ReadCloser{Reader: buf, CloseFunc: rc.Close}

	// Should be enough to read first block?
	zb, err := buf.Peek(1 << 16)
	if err != nil {
		if err != io.EOF {
			return "", pr, nil, fmt.Errorf("buf.Peek: %w", err)
		}
	}

	br := bytes.NewReader(zb)
	if ok, zpr, err := gzip.Peek(br); err != nil {
		return "", pr, nil, fmt.Errorf("gzip.Peek: %w", err)
	} else if ok {
		zr, err := ogzip.NewReader(zpr)
		if err != nil {
			return "", pr, nil, err
		}
		ok, tpr, err := tarPeek(zr)
		if err != nil {
			return "", pr, nil, fmt.Errorf("tar.Peek: %w", err)
		}
		if ok {
			return "tar+gzip", pr, tpr, nil
		} else {
			return "gzip", pr, tpr, nil
		}
	}

	br = bytes.NewReader(zb)
	if ok, zpr, err := zstdPeek(br); err != nil {
		return "", pr, nil, fmt.Errorf("zstd.Peek: %w", err)
	} else if ok {
		log.Printf("looks like zstd")
		zr, err := kzstd.NewReader(zpr)
		if err != nil {
			return "", pr, nil, err
		}
		ok, tpr, err := tarPeek(zr.IOReadCloser())
		if err != nil {
			return "", pr, nil, fmt.Errorf("tarPeek: %w", err)
		}
		if ok {
			return "tar+zstd", pr, tpr, nil
		} else {
			return "zstd", pr, tpr, nil
		}
	}

	br = bytes.NewReader(zb)
	if ok, tpr, err := tarPeek(io.NopCloser(br)); err != nil {
		return "", pr, nil, fmt.Errorf("tarpeek: %w", err)
	} else if ok {
		return "tar", pr, tpr, nil
	}

	return "", pr, nil, nil
}

func zstdPeek(r io.Reader) (bool, PeekReader, error) {
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
func checkHeader(pr PeekReader, expectedHeader []byte) (bool, PeekReader, error) {
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

func tarPeek(rc io.ReadCloser) (bool, io.ReadCloser, error) {
	// Make sure it's more than 512
	var pr PeekReader
	if p, ok := rc.(PeekReader); ok {
		pr = p
	} else {
		// For tar peek.
		pr = bufio.NewReaderSize(rc, 1<<16)
	}
	prc := &and.ReadCloser{Reader: pr, CloseFunc: rc.Close}

	block, err := pr.Peek(512)
	if err != nil {
		// https://github.com/google/go-containerregistry/issues/367
		if err == io.EOF {
			if len(block) == 0 {
				return true, prc, nil
			}
			return false, prc, nil
		}
		return false, prc, fmt.Errorf("tar.Peek(512): %w", err)
	}

	magic := string(block[257:][:6])
	isTar := magic == magicGNU || magic == magicUSTAR
	if !isTar {
		block, _ := pr.Peek(1024)
		if len(block) == 1024 && isZeroes(block) {
			log.Printf("this looks like an empty tar")
			return true, prc, nil
		}
	}
	return isTar, prc, nil
}

func isZeroes(block []byte) bool {
	for _, b := range block {
		if b != 0 {
			return false
		}
	}

	return true
}
