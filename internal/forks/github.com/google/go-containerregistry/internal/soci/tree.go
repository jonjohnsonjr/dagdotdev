package soci

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"strings"
	"time"

	"github.com/google/go-containerregistry/internal/and"
	"github.com/google/go-containerregistry/internal/compress/gzip"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/klauspost/compress/zstd"
)

type Index interface {
	Dict(cp *Checkpointer) ([]byte, error)
	Locate(name string) (*TOCFile, error)
	TOC() *TOC
}

type tree struct {
	toc *TOC

	// BlobSeeker for _index_ files.
	bs BlobSeeker

	sub Index
}

func NewIndex(bs BlobSeeker, toc *TOC, sub Index) (Index, error) {
	if sub == nil {
		return newLeaf(bs, toc)
	}

	t := &tree{
		bs:  bs,
		sub: sub,
	}

	if toc != nil {
		t.toc = toc
		return t, nil
	}

	rc, err := t.Open(tocFile)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	toc = &TOC{}
	dec := json.NewDecoder(rc)
	if err := dec.Decode(toc); err != nil {
		return nil, err
	}
	toc.Size = dec.InputOffset()
	t.toc = toc
	if t.toc.Type == "" {
		t.toc.Type = "tar+gzip"
	}
	return t, nil
}

func (t *tree) TOC() *TOC {
	return t.toc
}

func dictFile(i int) string {
	return fmt.Sprintf("%05d.dict", i)
}

const tocFile = "toc.json"

func (t *tree) Open(name string) (io.ReadCloser, error) {
	logs.Debug.Printf("tree.Open(%q)", name)
	start := time.Now()
	defer func() {
		log.Printf("tree.Open(%q) (%s)", name, time.Since(start))
	}()
	tf, err := t.sub.Locate(name)
	if err != nil {
		return nil, err
	}

	return ExtractFile(context.TODO(), t.sub, t.bs, tf)
}

// TODO: Make things other than dict access lazy.
func (t *tree) Dict(cp *Checkpointer) ([]byte, error) {
	if cp.index == 0 || cp.checkpoint.IsEmpty() {
		return nil, nil
	}
	if hist := cp.checkpoint.History(); hist != nil {
		return hist, nil
	}

	filename := dictFile(cp.index)
	rc, err := t.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("Open(%q): %w", filename, err)
	}
	defer rc.Close()

	b, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("Open(%q).ReadAll(): %w", filename, err)
	}
	cp.checkpoint.SetHistory(b)

	return b, nil
}

func ExtractFile(ctx context.Context, t Index, bs BlobSeeker, tf *TOCFile) (io.ReadCloser, error) {
	start := time.Now()
	defer func() {
		log.Printf("ExtractFile(%q) (%s)", tf.Name, time.Since(start))
	}()
	if tf.Size == 0 {
		return io.NopCloser(bytes.NewReader([]byte{})), nil
	}
	cp := t.TOC().Checkpoint(tf)
	dict, err := t.Dict(cp)
	if err != nil {
		return nil, fmt.Errorf("Dict(): %w", err)
	}

	rc, err := bs.Reader(ctx, cp.start, cp.end)
	if err != nil {
		return nil, fmt.Errorf("Reader(): %w", err)
	}

	from := cp.checkpoint
	from.SetHistory(dict)

	kind := t.TOC().Type
	logs.Debug.Printf("Type = %q", kind)
	if kind == "tar" {
		logs.Debug.Printf("ExtractFile: Returning LimitedReader of size %d", cp.tf.Size)
		lr := io.LimitedReader{rc, cp.tf.Size}
		return &and.ReadCloser{&lr, rc.Close}, nil
	}

	var r io.ReadCloser
	if kind == "tar+zstd" {
		// TODO: zstd.Continue
		logs.Debug.Printf("ExtractFile: zstd+tar")
		zr, err := zstd.NewReader(rc)
		if err != nil {
			return nil, err
		}
		r = zr.IOReadCloser()
	} else {
		logs.Debug.Printf("ExtractFile: Calling gzip.Continue")
		r, err = gzip.Continue(rc, 1<<22, from, nil)
		if err != nil {
			return nil, err
		}
	}

	start2 := time.Now()
	logs.Debug.Printf("ExtractFile: Discarding %d bytes", cp.discard)
	n, err := io.CopyN(io.Discard, r, cp.discard)
	if err != nil {
		return nil, err
	}
	log.Printf("Discarded %d bytes before %q (%s)", n, tf.Name, time.Since(start2))

	logs.Debug.Printf("ExtractFile: Returning LimitedReader of size %d", cp.tf.Size)
	lr := io.LimitedReader{r, cp.tf.Size}
	return &and.ReadCloser{&lr, rc.Close}, nil
}

func (t *tree) Locate(name string) (*TOCFile, error) {
	for _, f := range t.toc.Files {
		if f.Name == name {
			return &f, nil
		}
	}

	return nil, fs.ErrNotExist
}

type leaf struct {
	bs BlobSeeker

	dicts map[string][]byte
	toc   *TOC
}

func newLeaf(bs BlobSeeker, toc *TOC) (*leaf, error) {
	t := &leaf{
		bs:  bs,
		toc: toc,
	}
	if toc == nil {
		return t, t.init()
	}
	return t, nil
}

func (t *leaf) init() error {
	start := time.Now()
	defer func() {
		log.Printf("leaf.init() (%s)", time.Since(start))
	}()
	t.dicts = map[string][]byte{}
	rc, err := t.bs.Reader(context.TODO(), 0, -1)
	if err != nil {
		return fmt.Errorf("Reader(): %w", err)
	}
	defer rc.Close()

	zr, err := gzip.NewReader(rc)
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if strings.HasSuffix(header.Name, ".dict") {
			b, err := io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("%s ReadAll: %w", header.Name, err)
			}
			t.dicts[header.Name] = b
		} else if header.Name == tocFile {
			if t.toc != nil {
				break
			}

			t.toc = &TOC{}
			if err := json.NewDecoder(tr).Decode(t.toc); err != nil {
				return fmt.Errorf("Decode toc: %w", err)
			}
			t.toc.Size = header.Size
			t.toc.ArchiveSize = zr.UncompressedCount()
			if t.toc.Type == "" {
				t.toc.Type = "tar+gzip"
			}
		}
	}

	return nil
}

func (t *leaf) Dict(cp *Checkpointer) ([]byte, error) {
	if cp.checkpoint.IsEmpty() {
		return nil, nil
	}
	if hist := cp.checkpoint.History(); hist != nil {
		return hist, nil
	}
	if t.dicts == nil {
		if err := t.init(); err != nil {
			return nil, fmt.Errorf("init(): %w", err)
		}
	}

	dictName := dictFile(cp.index)
	hist, ok := t.dicts[dictName]
	if !ok {
		return nil, fmt.Errorf("Dict(%d), %q not found", cp.index, dictName)
	}

	cp.checkpoint.SetHistory(hist)

	return hist, nil
}

func (t *leaf) Locate(name string) (*TOCFile, error) {
	if t.toc == nil {
		if err := t.init(); err != nil {
			return nil, err
		}
	}
	for _, f := range t.toc.Files {
		if f.Name == name {
			return &f, nil
		}
	}

	return nil, fs.ErrNotExist
}

func (t *leaf) TOC() *TOC {
	return t.toc
}
