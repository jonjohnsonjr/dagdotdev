package soci

import (
	"archive/tar"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"

	ogzip "compress/gzip"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/jonjohnsonjr/dagdotdev/internal/and"
	"github.com/jonjohnsonjr/dagdotdev/internal/forks/compress/flate"
	"github.com/jonjohnsonjr/dagdotdev/internal/forks/compress/gzip"
	"golang.org/x/sync/errgroup"
)

type Indexer struct {
	toc      *TOC
	updates  chan *flate.Checkpoint
	zupdates chan *zstd.Checkpoint
	g        errgroup.Group
	in       io.ReadCloser
	zr       checkpointReader
	tr       *tar.Reader
	w        io.WriteCloser
	bw       io.Writer
	tw       *tar.Writer
	zw       *ogzip.Writer
	cw       *countWriter
	finished bool
	written  bool
}

// Returns:
// Indexer (if non-nil, everything else is nil)
// Original stream (buffered rc to Peek)
// Unwrapped stream (ungzip or unzstd, nil if we could not unwrap or err != nil)
// Error (maybe nil)
func NewIndexer(rc io.ReadCloser, w io.Writer, span int64, mediaType string) (*Indexer, string, io.ReadCloser, io.ReadCloser, error) {
	logs.Debug.Printf("NewIndexer")

	kind, pr, tpr, err := Peek(rc)
	if err != nil {
		return nil, kind, pr, tpr, fmt.Errorf("Peek: %w", err)
	}

	logs.Debug.Printf("Peeked: %q", kind)
	if kind == "" {
		// Not a wrapped tar!
		return nil, kind, pr, tpr, nil
	}

	// TODO: Allow binding writer after detection.

	toc := &TOC{
		Files:       []TOCFile{},
		Checkpoints: []*flate.Checkpoint{},
		Ssize:       span,
		MediaType:   mediaType,
	}

	i := &Indexer{
		toc: toc,
		in:  rc,
	}

	bw := bufio.NewWriterSize(w, 1<<16)
	zw, err := ogzip.NewWriterLevel(bw, ogzip.BestSpeed)
	if err != nil {
		return nil, "", nil, nil, err
	}
	flushClose := func() error {
		return errors.Join(zw.Close(), bw.Flush())
	}

	i.bw = bw
	i.zw = zw
	i.w = &and.WriteCloser{zw, flushClose}

	if kind == "tar+gzip" {
		i.updates = make(chan *flate.Checkpoint, 10)
		zr, err := gzip.NewReaderWithSpans(pr, span, i.updates)
		if err != nil {
			return nil, kind, pr, nil, fmt.Errorf("gzip.NewReader: %w", err)
		}

		i.zr = zr
		i.tr = tar.NewReader(zr)
	} else if kind == "tar+zstd" {
		i.zupdates = make(chan *zstd.Checkpoint, 10)
		zr, err := zstd.NewReader(pr, zstd.WithCheckpoints(i.zupdates), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, kind, pr, nil, fmt.Errorf("zstd.NewReader: %w", err)
		}
		i.zr = zr
		i.tr = tar.NewReader(zr)
	} else if kind == "tar" {
		i.zr = &countReader{pr, 0}
		i.tr = tar.NewReader(i.zr)
	} else {
		// Not a wrapped tar!
		return nil, kind, pr, tpr, nil
	}

	i.toc.Type = kind

	i.cw = &countWriter{i.w, 0}
	i.tw = tar.NewWriter(i.cw)

	i.g.Go(i.processUpdates)

	return i, kind, nil, nil, nil
}

func (i *Indexer) Next() (*tar.Header, error) {
	header, err := i.tr.Next()
	if errors.Is(err, io.EOF) {
		if !i.finished {
			if _, err := io.Copy(io.Discard, i.zr); err != nil {
				return nil, err
			}
			if i.updates != nil {
				close(i.updates)
			} else if i.zupdates != nil {
				close(i.zupdates)
			}
			i.finished = true
		}
		return nil, err
	} else if err != nil {
		return nil, err
	}
	f := FromTar(header)
	f.Offset = i.zr.UncompressedCount()
	// logs.Debug.Printf("file: %q, read: %d", header.Name, f.Offset)
	i.toc.Files = append(i.toc.Files, *f)
	return header, err
}

func (i *Indexer) Read(p []byte) (int, error) {
	return i.tr.Read(p)
}

func (i *Indexer) Close() error {
	// TODO: racey?
	return errors.Join(i.in.Close(), i.w.Close())
}

func (i *Indexer) Size() int64 {
	return i.cw.n
}

func (i *Indexer) Type() string {
	return i.toc.Type
}

func (i *Indexer) TOC() (*TOC, error) {
	if i.written {
		return i.toc, nil
	}
	if err := i.g.Wait(); err != nil {
		return nil, err
	}

	i.toc.Csize = i.zr.CompressedCount()
	i.toc.Usize = i.zr.UncompressedCount()

	b, err := json.Marshal(i.toc)
	if err != nil {
		return nil, err
	}
	tocSize := int64(len(b))
	if err := i.tw.WriteHeader(&tar.Header{
		Name: tocFile,
		Size: tocSize,
	}); err != nil {
		return nil, err
	}

	// Reset our gzip writer to force a checkpoint right before TOC.
	// This allows us to seek here for free if we index this index.
	if err := i.zw.Close(); err != nil {
		return nil, err
	}
	i.zw.Reset(i.bw)

	if _, err := i.tw.Write(b); err != nil {
		return nil, err
	}
	if err := i.tw.Close(); err != nil {
		return nil, err
	}
	if err := i.w.Close(); err != nil {
		return nil, err
	}

	i.written = true
	i.toc.ArchiveSize = i.cw.n
	i.toc.Size = tocSize

	return i.toc, nil
}

func (i *Indexer) processUpdates() error {
	if i.updates != nil {
		for update := range i.updates {
			u := update

			if !u.Empty {
				b := u.Hist
				f := dictFile(len(i.toc.Checkpoints))

				if err := i.tw.WriteHeader(&tar.Header{
					Name: f,
					Size: int64(len(b)),
				}); err != nil {
					return err
				}
				// Reset our gzip writer to force a checkpoint right before this.
				// This allows us to seek here for free if we index this index.
				if err := i.zw.Close(); err != nil {
					return err
				}
				i.zw.Reset(i.bw)

				if _, err := i.tw.Write(b); err != nil {
					return err
				}
				u.Hist = nil
			}

			i.toc.Checkpoints = append(i.toc.Checkpoints, u)
		}
	}
	// TODO: uhhh
	if i.zupdates != nil {
		for update := range i.zupdates {
			u := flate.Checkpoint{
				In:    update.In,
				Out:   update.Out,
				Empty: update.Empty,
			}
			i.toc.Checkpoints = append(i.toc.Checkpoints, &u)
		}
	}
	return nil
}

type checkpointReader interface {
	io.Reader
	CompressedCount() int64
	UncompressedCount() int64
}

type Checkpoint interface {
	BytesRead() int64
	BytesWritten() int64
	History() []byte
	SetHistory([]byte)
	IsEmpty() bool
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (n int, err error) {
	n, err = c.r.Read(p)
	c.n += int64(n)
	return
}

func (c *countReader) CompressedCount() int64 {
	return 0
}

func (c *countReader) UncompressedCount() int64 {
	return c.n
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	c.n += int64(n)
	return
}
