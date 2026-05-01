// Package blobcache provides reference soci.BlobStore and soci.TOCCache
// implementations backed by GCS, the local filesystem, and in-memory storage.
package blobcache

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/logs"
	"github.com/jonjohnsonjr/dagdotdev/pkg/soci"
)

var (
	_ soci.BlobStore = (*GCS)(nil)
	_ soci.BlobStore = (*Dir)(nil)
	_ soci.BlobStore = (*Multi)(nil)

	_ soci.TOCCache = (*GCS)(nil)
	_ soci.TOCCache = (*Dir)(nil)
	_ soci.TOCCache = (*Mem)(nil)
)

// debug controls per-call timing logs on slow backends.
var debug = false

// BuildIndexCache returns a BlobStore configured from environment variables:
// CACHE_DIR (local filesystem path) or CACHE_BUCKET (GCS bucket, "gs://" prefix
// optional). gcsPathPrefix scopes GCS objects under <bucket>/<gcsPathPrefix>/...
// so different consumers can share a bucket. If neither env var is set, returns
// an empty Multi that I/O-fails every operation.
func BuildIndexCache(gcsPathPrefix string) soci.BlobStore {
	stores := []soci.BlobStore{}

	if cd := os.Getenv("CACHE_DIR"); cd != "" {
		logs.Debug.Printf("CACHE_DIR=%q", cd)
		stores = append(stores, NewDir(cd))
	} else if cb := os.Getenv("CACHE_BUCKET"); cb != "" {
		logs.Debug.Printf("CACHE_BUCKET=%q", cb)
		if g, err := NewGCS(context.Background(), cb, gcsPathPrefix); err != nil {
			logs.Debug.Printf("NewGCS(): %v", err)
		} else {
			stores = append(stores, g)
		}
	}
	return NewMulti(stores...)
}

// BuildTOCCache returns the default in-memory TOC cache.
// Sized for ~50 entries × 50 MB max each (~2.5 GB upper bound).
func BuildTOCCache() soci.TOCCache {
	return NewMem(50*(1<<20), 50)
}

// GCS is a BlobStore + TOCCache backed by a GCS bucket. Object layout:
//   <bucket>/<pathPrefix>/<key-with-colons-replaced>/toc.json.gz   for TOCs
//   <bucket>/<pathPrefix>/<key-with-colons-replaced>.tar.gz        for blobs
type GCS struct {
	client     *storage.Client
	bucket     *storage.BucketHandle
	pathPrefix string
}

// NewGCS returns a GCS-backed cache. pathPrefix scopes objects under
// <bucket>/<pathPrefix>/... — pass a per-consumer string ("soci", "apk", etc.)
// to namespace shared buckets.
func NewGCS(ctx context.Context, bucket, pathPrefix string) (*GCS, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	bkt := client.Bucket(strings.TrimPrefix(bucket, "gs://"))
	return &GCS{client: client, bucket: bkt, pathPrefix: pathPrefix}, nil
}

func (g *GCS) tocPath(key string) string {
	return path.Join(g.pathPrefix, strings.Replace(key, ":", "-", 1), "toc.json.gz")
}

func (g *GCS) blobPath(key string) string {
	return path.Join(g.pathPrefix, strings.Replace(key, ":", "-", 1)) + ".tar.gz"
}

// TODO: Use lifecycle with bumping timestamps to evict old data.
func (g *GCS) Get(ctx context.Context, key string) (*soci.TOC, error) {
	if debug {
		start := time.Now()
		defer func() { log.Printf("bucket.Get(%q) (%s)", key, time.Since(start)) }()
	}
	rc, err := g.bucket.Object(g.tocPath(key)).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	zr, err := gzip.NewReader(rc)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	toc := &soci.TOC{}
	if err := json.NewDecoder(zr).Decode(toc); err != nil {
		return nil, err
	}
	return toc, nil
}

func (g *GCS) Put(ctx context.Context, key string, toc *soci.TOC) error {
	if debug {
		start := time.Now()
		defer func() { log.Printf("bucket.Put(%q) (%s)", key, time.Since(start)) }()
	}
	w := g.bucket.Object(g.tocPath(key)).NewWriter(ctx)

	// TODO: Ideally we'd fork gzip.Writer and flush at checkpoints to create
	// very small second-order indexes.
	zw, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		logs.Debug.Printf("gzip.NewWriter() = %v", err)
		return err
	}
	if err := json.NewEncoder(zw).Encode(toc); err != nil {
		logs.Debug.Printf("Encode() = %v", err)
		zw.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		logs.Debug.Printf("zw.Close() = %v", err)
		return err
	}
	return w.Close()
}

func (g *GCS) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	return g.bucket.Object(g.blobPath(key)).NewWriter(ctx), nil
}

func (g *GCS) Reader(ctx context.Context, key string) (io.ReadCloser, error) {
	return g.bucket.Object(g.blobPath(key)).NewReader(ctx)
}

func (g *GCS) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	return g.bucket.Object(g.blobPath(key)).NewRangeReader(ctx, offset, length)
}

func (g *GCS) Size(ctx context.Context, key string) (int64, error) {
	if debug {
		start := time.Now()
		defer func() { log.Printf("bucket.Size(%q) (%s)", key, time.Since(start)) }()
	}
	attrs, err := g.bucket.Object(g.blobPath(key)).Attrs(ctx)
	if err != nil {
		return -1, err
	}
	return attrs.Size, nil
}

// Dir is a BlobStore + TOCCache backed by a local filesystem directory.
type Dir struct {
	dir string
}

// NewDir returns a Dir rooted at dir. Files are named by key with ":" → "-"
// and a per-method extension (.toc.json.gz / .tar.gz).
func NewDir(dir string) *Dir {
	return &Dir{dir: dir}
}

func (d *Dir) file(key string) string {
	return filepath.Join(d.dir, strings.Replace(key, ":", "-", 1))
}

func (d *Dir) Get(ctx context.Context, key string) (*soci.TOC, error) {
	f, err := os.Open(d.file(key) + ".toc.json.gz")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	toc := &soci.TOC{}
	if err := json.NewDecoder(zr).Decode(toc); err != nil {
		return nil, err
	}
	return toc, nil
}

func (d *Dir) Put(ctx context.Context, key string, toc *soci.TOC) error {
	f, err := os.OpenFile(d.file(key)+".toc.json.gz", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer f.Close()
	zw, err := gzip.NewWriterLevel(f, gzip.BestSpeed)
	if err != nil {
		return err
	}
	defer zw.Close()
	return json.NewEncoder(zw).Encode(toc)
}

func (d *Dir) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	tmp, err := os.CreateTemp(d.dir, key)
	if err != nil {
		return nil, err
	}
	return &dirWriter{dst: d.file(key) + ".tar.gz", f: tmp}, nil
}

func (d *Dir) Reader(ctx context.Context, key string) (io.ReadCloser, error) {
	logs.Debug.Printf("Dir.Reader(%q)", key)
	return os.Open(d.file(key) + ".tar.gz")
}

func (d *Dir) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	f, err := os.Open(d.file(key) + ".tar.gz")
	if err != nil {
		return nil, err
	}
	return io.NopCloser(io.NewSectionReader(f, offset, length)), nil
}

func (d *Dir) Size(ctx context.Context, key string) (int64, error) {
	stat, err := os.Stat(d.file(key) + ".tar.gz")
	if err != nil {
		return -1, err
	}
	return stat.Size(), nil
}

type dirWriter struct {
	dst string
	f   *os.File
}

func (d *dirWriter) Write(p []byte) (int, error) { return d.f.Write(p) }

func (d *dirWriter) Close() error {
	if err := d.f.Close(); err != nil {
		return fmt.Errorf("closing: %w", err)
	}
	if err := os.Rename(d.f.Name(), d.dst); err != nil {
		return fmt.Errorf("renaming: %w", err)
	}
	return nil
}

// Mem is an in-memory TOCCache. Entries are evicted by LRU when entryCap is
// reached; TOCs larger than maxSize bytes are silently dropped on Put.
type Mem struct {
	sync.Mutex
	maxSize  int64
	entryCap int
	entries  []*memEntry
}

type memEntry struct {
	key    string
	toc    *soci.TOC
	access time.Time
}

// NewMem returns an in-memory TOCCache.
func NewMem(maxSize int64, entryCap int) *Mem {
	return &Mem{maxSize: maxSize, entryCap: entryCap}
}

func (m *Mem) Get(ctx context.Context, key string) (*soci.TOC, error) {
	m.Lock()
	defer m.Unlock()
	for _, e := range m.entries {
		if e.key == key {
			e.access = time.Now()
			return e.toc, nil
		}
	}
	return nil, io.EOF
}

func (m *Mem) Put(ctx context.Context, key string, toc *soci.TOC) error {
	logs.Debug.Printf("Mem.Put(%q) at %d bytes", key, toc.Size)
	m.Lock()
	defer m.Unlock()
	if toc.Size > m.maxSize {
		logs.Debug.Printf("toc.Size = %d, m.maxSize = %d", toc.Size, m.maxSize)
		return nil
	}

	e := &memEntry{key: key, toc: toc, access: time.Now()}
	if len(m.entries) >= m.entryCap {
		min, idx := e.access, -1
		for i, ee := range m.entries {
			if ee.access.Before(min) {
				min = ee.access
				idx = i
			}
		}
		m.entries[idx] = e
		return nil
	}
	m.entries = append(m.entries, e)
	return nil
}

// Multi is a BlobStore that tries each underlying store in order. Reader/Size
// fall through to the next store on miss; Writer fans out to all of them.
type Multi struct {
	stores []soci.BlobStore
}

// NewMulti returns a Multi over the given stores (lower-priority first).
func NewMulti(stores ...soci.BlobStore) *Multi {
	return &Multi{stores: stores}
}

func (m *Multi) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	writers := []io.WriteCloser{}
	for _, s := range m.stores {
		w, err := s.Writer(ctx, key)
		if err != nil {
			return nil, err
		}
		writers = append(writers, w)
	}
	return multiWriter(writers...), nil
}

func (m *Multi) Reader(ctx context.Context, key string) (io.ReadCloser, error) {
	for _, s := range m.stores {
		rc, err := s.Reader(ctx, key)
		if err == nil {
			return rc, nil
		}
		logs.Debug.Printf("multi[%T].Reader(%q) = %v", s, key, err)
	}
	return nil, io.EOF
}

func (m *Multi) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	for _, s := range m.stores {
		var (
			rc  io.ReadCloser
			err error
		)
		if offset == 0 && length == -1 {
			rc, err = s.Reader(ctx, key)
		} else {
			rc, err = s.RangeReader(ctx, key, offset, length)
		}
		if err == nil {
			return rc, nil
		}
		logs.Debug.Printf("multi[%T].RangeReader(%q) = %v", s, key, err)
	}
	return nil, io.EOF
}

func (m *Multi) Size(ctx context.Context, key string) (int64, error) {
	for _, s := range m.stores {
		sz, err := s.Size(ctx, key)
		if err == nil {
			return sz, nil
		}
		logs.Debug.Printf("multi[%T].Size(%q) = %v", s, key, err)
	}
	return -1, io.EOF
}

type multiW struct {
	writers []io.WriteCloser
}

func (mw *multiW) Write(p []byte) (int, error) {
	for _, w := range mw.writers {
		n, err := w.Write(p)
		if err != nil {
			return n, err
		}
		if n != len(p) {
			return n, io.ErrShortWrite
		}
	}
	return len(p), nil
}

func (mw *multiW) Close() error {
	errs := []error{}
	for _, w := range mw.writers {
		if err := w.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func multiWriter(writers ...io.WriteCloser) io.WriteCloser {
	flat := make([]io.WriteCloser, 0, len(writers))
	for _, w := range writers {
		if mw, ok := w.(*multiW); ok {
			flat = append(flat, mw.writers...)
		} else {
			flat = append(flat, w)
		}
	}
	return &multiW{flat}
}

