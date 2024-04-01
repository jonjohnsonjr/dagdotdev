package xxd

import (
	"bufio"
	"fmt"
	"io"
)

var (
	amp = []byte("&amp;")
	lt  = []byte("&lt;")
	gt  = []byte("&gt;")
	dq  = []byte("&#34;")
	sq  = []byte("&#39;")
)

func NewWriter(w io.Writer, size int64) *Writer {
	return &Writer{
		buf:  bufio.NewWriter(w),
		size: size,
	}
}

type Writer struct {
	buf    *bufio.Writer
	size   int64
	cursor int64
	ascii  []byte
}

func (w *Writer) Write(p []byte) (n int, err error) {
	for _, r := range p {
		if w.size != 0 && w.cursor >= w.size {
			break
		}
		if w.cursor%16 == 0 {
			line := fmt.Sprintf("%08x:", w.cursor)
			if _, err := w.buf.WriteString(line); err != nil {
				return 0, err
			}
			w.ascii = []byte{' ', ' '}
		}
		if w.cursor%2 == 0 {
			if err := w.buf.WriteByte(' '); err != nil {
				return 0, err
			}
		}

		if r < 32 || r > 126 {
			w.ascii = append(w.ascii, '.')
		} else {
			switch r {
			case '&':
				w.ascii = append(w.ascii, amp...)
			case '<':
				w.ascii = append(w.ascii, lt...)
			case '>':
				w.ascii = append(w.ascii, gt...)
			case '"':
				w.ascii = append(w.ascii, dq...)
			case '\'':
				w.ascii = append(w.ascii, sq...)
			default:
				w.ascii = append(w.ascii, r)
			}
		}

		w.cursor++

		line := fmt.Sprintf("%02x", r)
		if _, err := w.buf.WriteString(line); err != nil {
			return 0, err
		}
		if w.cursor%16 == 0 {
			w.ascii = append(w.ascii, '\n')
			if _, err := w.buf.Write(w.ascii); err != nil {
				return 0, err
			}
		}
	}

	if w.size > 0 && w.cursor >= w.size {
		pos := w.size % 16
		if pos != 0 {
			for i := pos; i < 16; i++ {
				if i%2 == 0 {
					if err := w.buf.WriteByte(' '); err != nil {
						return 0, err
					}
				}
				if _, err := w.buf.Write([]byte("  ")); err != nil {
					return 0, err
				}
			}
			if _, err := w.buf.Write(w.ascii); err != nil {
				return 0, err
			}
		}
	}

	return len(p), w.buf.Flush()
}
