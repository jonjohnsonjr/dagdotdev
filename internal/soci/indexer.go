package soci

import (
	"archive/tar"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"

	ogzip "compress/gzip"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/jonjohnsonjr/dagdotdev/internal/and"
	"github.com/jonjohnsonjr/dagdotdev/internal/forks/compress/flate"
	"github.com/jonjohnsonjr/dagdotdev/internal/forks/compress/gzip"
	httpserve "github.com/jonjohnsonjr/dagdotdev/internal/forks/http"
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
	done     bool
	written  bool

	cond *sync.Cond
}

// Returns:
// Indexer (if non-nil, everything else is nil)
// Original stream (buffered rc to Peek)
// Unwrapped stream (ungzip or unzstd, nil if we could not unwrap or err != nil)
// Error (maybe nil)
func NewIndexer(rc io.ReadCloser, w io.Writer, span int64, mediaType string) (*Indexer, io.ReadCloser, io.ReadCloser, error) {
	logs.Debug.Printf("NewIndexer")

	kind, pr, tpr, err := Peek(rc)
	if err != nil {
		return nil, pr, tpr, fmt.Errorf("Peek: %w", err)
	}

	logs.Debug.Printf("Peeked: %q", kind)
	if kind == "" {
		// Not a wrapped tar!
		return nil, pr, tpr, nil
	}

	// TODO: Allow binding writer after detection.

	toc := &TOC{
		Files:       []TOCFile{},
		Checkpoints: []*flate.Checkpoint{},
		Ssize:       span,
		MediaType:   mediaType,
	}

	i := &Indexer{
		toc:  toc,
		in:   rc,
		cond: sync.NewCond(&sync.Mutex{}),
	}

	bw := bufio.NewWriterSize(w, 1<<16)
	zw, err := ogzip.NewWriterLevel(bw, ogzip.BestSpeed)
	if err != nil {
		return nil, nil, nil, err
	}
	flushClose := func() error {
		return errors.Join(zw.Close(), bw.Flush())
	}

	i.bw = bw
	i.zw = zw
	i.w = &and.WriteCloser{
		Writer:    zw,
		CloseFunc: flushClose,
	}

	if kind == "tar+gzip" {
		i.updates = make(chan *flate.Checkpoint, 10)
		zr, err := gzip.NewReaderWithSpans(pr, span, i.updates)
		if err != nil {
			return nil, pr, nil, fmt.Errorf("gzip.NewReader: %w", err)
		}

		i.zr = zr
		i.tr = tar.NewReader(zr)
	} else if kind == "tar+zstd" {
		i.zupdates = make(chan *zstd.Checkpoint, 10)
		zr, err := zstd.NewReader(pr, zstd.WithCheckpoints(i.zupdates), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, pr, nil, fmt.Errorf("zstd.NewReader: %w", err)
		}
		i.zr = zr
		i.tr = tar.NewReader(zr)
	} else if kind == "tar" {
		i.zr = &countReader{pr, 0}
		i.tr = tar.NewReader(i.zr)
	} else {
		// Not a wrapped tar!
		return nil, pr, tpr, nil
	}

	i.toc.Type = kind

	i.cw = &countWriter{i.w, 0}
	i.tw = tar.NewWriter(i.cw)

	i.g.Go(i.processUpdates)

	return i, nil, nil, nil
}

func (i *Indexer) Next() (*tar.Header, error) {
	header, err := i.tr.Next()
	if errors.Is(err, io.EOF) {
		if !i.finished() {
			if _, err := io.Copy(io.Discard, i.zr); err != nil {
				return nil, err
			}
			if i.updates != nil {
				close(i.updates)
			} else if i.zupdates != nil {
				close(i.zupdates)
			}
			i.finish()
		}
		return nil, err
	} else if err != nil {
		return nil, err
	}
	f := FromTar(header)
	f.Offset = i.zr.UncompressedCount()
	// logs.Debug.Printf("file: %q, read: %d", header.Name, f.Offset)
	i.toc.Files = append(i.toc.Files, *f)

	i.cond.Broadcast()

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

func (i *Indexer) finished() bool {
	i.cond.L.Lock()
	defer i.cond.L.Unlock()

	return i.done
}

func (i *Indexer) finish() {
	i.cond.L.Lock()
	defer i.cond.L.Unlock()

	i.done = true
}

func (i *Indexer) wait() bool {
	i.cond.L.Lock()
	defer i.cond.L.Unlock()

	if i.done {
		return true
	}

	i.cond.Wait()

	return i.done
}

func (i *Indexer) FS(in io.ReadCloser) *indexFS {
	return &indexFS{
		idx: i,
		in:  in,
	}
}

type indexFS struct {
	idx *Indexer
	in  io.ReadCloser
}

func (i *indexFS) Open(name string) (httpserve.File, error) {
	return &indexFile{
		name: name,
		fs:   i,
	}, nil
}

type indexFile struct {
	name string
	fs   *indexFS
}

// This used to try to handle Seeking, but it was complicated, so I
// forked net/http instead.
func (f *indexFile) Seek(offset int64, whence int) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

func (f *indexFile) Read(p []byte) (int, error) {
	// TODO: Can we support this?
	return 0, fmt.Errorf("not implemented")
}

func (f *indexFile) Readdir(count int) ([]os.FileInfo, error) {
	// TODO: Can we support this?
	return nil, fmt.Errorf("not implemented")
}

func (f *indexFile) Stat() (os.FileInfo, error) {
	return dirInfo{f.name}, nil
}

func (f *indexFile) Close() error {
	return nil
}

func (f *indexFile) Root() bool {
	return f.name == "" || f.name == "/" || f.name == "/index.html"
}

func (f *indexFile) Files() iter.Seq2[fs.FileInfo, error] {
	logs.Debug.Printf("Files(%q)", f.name)

	prefix := path.Clean("/" + f.name)
	if f.Root() {
		prefix = "/"
	}

	sawDirs := map[string]struct{}{}
	return func(yield func(fs.FileInfo, error) bool) {
		i := 0
		for {
			if i >= len(f.fs.idx.toc.Files) {
				// TODO: Check if we're finished, otherwise cond wait.
				if f.fs.idx.wait() {
					return
				}

				continue
			}

			hdr := TarHeader(&f.fs.idx.toc.Files[i])
			i++

			name := path.Clean("/" + hdr.Name)

			if prefix != "/" && name != prefix && !strings.HasPrefix(name, prefix+"/") {
				continue
			}

			fdir := path.Dir(strings.TrimPrefix(name, prefix))
			if !(fdir == "/" || (fdir == "." && prefix == "/")) {
				if fdir != "" && fdir != "." {
					if fdir[0] == '/' {
						fdir = fdir[1:]
					}
					implicit := strings.Split(fdir, "/")[0]
					if implicit != "" {
						if _, ok := sawDirs[implicit]; ok {
							continue
						}
						sawDirs[implicit] = struct{}{}
						if !yield(dirInfo{implicit}, nil) {
							return
						}
						continue
					}
				}
			}

			if hdr.Typeflag == tar.TypeDir {
				dirname := strings.TrimPrefix(name, prefix)
				if dirname != "" && dirname != "." {
					if dirname[0] == '/' {
						dirname = dirname[1:]
					}
					if _, ok := sawDirs[dirname]; ok {
						continue
					}
					sawDirs[dirname] = struct{}{}
				}
			}

			if !yield(hdr.FileInfo(), nil) {
				return
			}
		}
	}
}
