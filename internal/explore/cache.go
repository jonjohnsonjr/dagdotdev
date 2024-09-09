package explore

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
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
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/jonjohnsonjr/dagdotdev/internal/soci"
)

type Cache interface {
	Get(context.Context, string) (*soci.TOC, error)
	Put(context.Context, string, *soci.TOC) error
}

// Streaming cache.
type cache interface {
	Cache
	Size(context.Context, string) (int64, error)
	Writer(context.Context, string) (io.WriteCloser, error)
	Reader(context.Context, string) (io.ReadCloser, error)
	RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error)
}

type cacheSeeker struct {
	cache cache
	key   string
}

func (bs *cacheSeeker) Reader(ctx context.Context, off int64, end int64) (io.ReadCloser, error) {
	logs.Debug.Printf("cacheSeeker.Reader(%d, %d)", off, end)
	return bs.cache.RangeReader(ctx, bs.key, off, end-off)
}

// TODO: We can separate the TOC from the checkpoints to avoid some buffering.
type gcsCache struct {
	client *storage.Client
	bucket *storage.BucketHandle
}

func (g *gcsCache) path(key string) string {
	return path.Join("soci", strings.Replace(key, ":", "-", 1), "toc.json.gz")
}

func (g *gcsCache) treePath(key string) string {
	return path.Join("soci", strings.Replace(key, ":", "-", 1)) + ".tar.gz"
}

func (g *gcsCache) object(key string) *storage.ObjectHandle {
	return g.bucket.Object(g.path(key))
}

// TODO: Use lifecycle with bumping timestamps to evict old data.
func (g *gcsCache) Get(ctx context.Context, key string) (*soci.TOC, error) {
	if debug {
		start := time.Now()
		defer func() {
			log.Printf("bucket.Get(%q) (%s)", key, time.Since(start))
		}()
	}
	rc, err := g.object(key).NewReader(ctx)
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

func (g *gcsCache) Put(ctx context.Context, key string, toc *soci.TOC) error {
	if debug {
		start := time.Now()
		defer func() {
			log.Printf("bucket.Put(%q) (%s)", key, time.Since(start))
		}()
	}
	w := g.object(key).NewWriter(ctx)

	// TODO: Ideally, we could fork gzip.Writer and flush at checkpoints
	// to create very very small second order indexes.
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

func (g *gcsCache) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	return g.bucket.Object(g.treePath(key)).NewWriter(ctx), nil
}

func (g *gcsCache) Reader(ctx context.Context, key string) (io.ReadCloser, error) {
	return g.bucket.Object(g.treePath(key)).NewReader(ctx)
}

func (g *gcsCache) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	return g.bucket.Object(g.treePath(key)).NewRangeReader(ctx, offset, length)
}

func (g *gcsCache) Size(ctx context.Context, key string) (int64, error) {
	if debug {
		start := time.Now()
		defer func() {
			log.Printf("bucket.Size(%q) (%s)", key, time.Since(start))
		}()
	}
	attrs, err := g.bucket.Object(g.treePath(key)).Attrs(ctx)
	if err != nil {
		return -1, err
	}
	return attrs.Size, nil
}

type dirCache struct {
	dir string
}

func (d *dirCache) file(key string) string {
	return filepath.Join(d.dir, strings.Replace(key, ":", "-", 1))
}

func (d *dirCache) Get(ctx context.Context, key string) (*soci.TOC, error) {
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

func (d *dirCache) Put(ctx context.Context, key string, toc *soci.TOC) error {
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

func (d *dirCache) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	tmp, err := os.CreateTemp(d.dir, key)
	if err != nil {
		return nil, err
	}

	return &dirWriter{
		dst: d.file(key) + ".tar.gz",
		f:   tmp,
	}, nil
}

func (d *dirCache) Reader(ctx context.Context, key string) (io.ReadCloser, error) {
	logs.Debug.Printf("dirCache.Reader(%q)", key)
	return os.Open(d.file(key) + ".tar.gz")
}

func (d *dirCache) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	f, err := os.Open(d.file(key) + ".tar.gz")
	if err != nil {
		return nil, err
	}
	return io.NopCloser(io.NewSectionReader(f, offset, length)), nil
}

func (d *dirCache) Size(ctx context.Context, key string) (int64, error) {
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

func (d *dirWriter) Write(p []byte) (n int, err error) {
	return d.f.Write(p)
}

func (d *dirWriter) Close() error {
	if err := d.f.Close(); err != nil {
		return fmt.Errorf("closing: %w", err)
	}
	if err := os.Rename(d.f.Name(), d.dst); err != nil {
		return fmt.Errorf("renaming: %w", err)
	}
	return nil
}

type memCache struct {
	sync.Mutex
	entryCap int
	maxSize  int64
	entries  []*cacheEntry
}

type cacheEntry struct {
	key    string
	toc    *soci.TOC
	buffer []byte
	size   int64
	access time.Time
}

func (m *memCache) get(ctx context.Context, key string) (*cacheEntry, error) {
	m.Lock()
	defer m.Unlock()

	for _, e := range m.entries {
		if e.key == key {
			e.access = time.Now()
			return e, nil
		}
	}
	return nil, io.EOF
}

func (m *memCache) Get(ctx context.Context, key string) (*soci.TOC, error) {
	e, err := m.get(ctx, key)
	if err != nil {
		return nil, err
	}

	return e.toc, nil
}

func (m *memCache) Put(ctx context.Context, key string, toc *soci.TOC) error {
	logs.Debug.Printf("memCache.Put(%q) at %d bytes", key, toc.Size)
	m.Lock()
	defer m.Unlock()
	if toc.Size > m.maxSize {
		logs.Debug.Printf("toc.Size = %d, m.maxSize = %d", toc.Size, m.maxSize)
		return nil
	}

	e := &cacheEntry{
		key:    key,
		toc:    toc,
		size:   toc.Size,
		access: time.Now(),
	}

	if len(m.entries) >= m.entryCap {
		min, idx := e.access, -1
		for i, e := range m.entries {
			if e.access.Before(min) {
				min = e.access
				idx = i
			}
		}
		m.entries[idx] = e
		return nil
	}

	m.entries = append(m.entries, e)
	return nil
}

func (m *memCache) New(ctx context.Context, key string) *cacheEntry {
	e := &cacheEntry{
		key:    key,
		access: time.Now(),
	}
	if len(m.entries) >= m.entryCap {
		min, idx := e.access, -1
		for i, e := range m.entries {
			if e.access.Before(min) {
				min = e.access
				idx = i
			}
		}
		m.entries[idx] = e
	} else {
		m.entries = append(m.entries, e)
	}
	return e
}

type memWriter struct {
	entry *cacheEntry
	buf   *bytes.Buffer
}

func (w *memWriter) Write(p []byte) (n int, err error) {
	return w.buf.Write(p)
}

func (w *memWriter) Close() (err error) {
	w.entry.buffer = w.buf.Bytes()
	return nil
}

func (m *memCache) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	e := m.New(ctx, key)
	mw := &memWriter{entry: e, buf: bytes.NewBuffer([]byte{})}
	return mw, nil
}

func (m *memCache) Reader(ctx context.Context, key string) (io.ReadCloser, error) {
	e, err := m.get(ctx, key)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(e.buffer)), nil
}

func (m *memCache) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	e, err := m.get(ctx, key)
	if err != nil {
		return nil, err
	}

	if offset == 0 && length == -1 {
		return m.Reader(ctx, key)
	}
	if e.buffer == nil || int64(len(e.buffer)) < offset+length+1 {
		return nil, io.EOF
	}
	return io.NopCloser(bytes.NewReader(e.buffer[offset : offset+length])), nil
}

func (m *memCache) Size(ctx context.Context, key string) (int64, error) {
	e, err := m.get(ctx, key)
	if err != nil {
		return -1, err
	}
	return int64(len(e.buffer)), nil
}

type multiCache struct {
	caches []cache
}

func (m *multiCache) Get(ctx context.Context, key string) (*soci.TOC, error) {
	for i, c := range m.caches {
		toc, err := c.Get(ctx, key)
		if err == nil {
			// Backfill previous misses (usually in mem).
			for j := i - 1; j >= 0; j-- {
				cache := m.caches[j]
				logs.Debug.Printf("filling %q in %T", key, cache)
				if err := cache.Put(ctx, key, toc); err != nil {
					logs.Debug.Printf("filling %q in %T = %v", key, cache, err)
				}
			}

			return toc, err
		} else {
			logs.Debug.Printf("multi[%T].Get(%q) = %v", c, key, err)
		}
	}

	return nil, io.EOF
}

// TODO: concurrent?
func (m *multiCache) Put(ctx context.Context, key string, toc *soci.TOC) error {
	errs := []error{}
	for _, c := range m.caches {
		err := c.Put(ctx, key, toc)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return Join(errs...)
}

func (m *multiCache) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	writers := []io.WriteCloser{}
	for _, c := range m.caches {
		w, err := c.Writer(ctx, key)
		if err != nil {
			return nil, err
		}
		writers = append(writers, w)
	}
	return MultiWriter(writers...), nil
}

// TODO: Does this make sense?
func (m *multiCache) Reader(ctx context.Context, key string) (io.ReadCloser, error) {
	for _, c := range m.caches {
		rc, err := c.Reader(ctx, key)
		if err == nil {
			return rc, nil
		} else {
			logs.Debug.Printf("multi[%T].Reader(%q) = %v", c, key, err)
		}
	}

	return nil, io.EOF
}

// TODO: Does this make sense?
func (m *multiCache) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	for _, c := range m.caches {
		var (
			rc  io.ReadCloser
			err error
		)
		if offset == 0 && length == -1 {
			rc, err = c.Reader(ctx, key)
		} else {
			rc, err = c.RangeReader(ctx, key, offset, length)
		}
		if err == nil {
			return rc, nil
		} else {
			logs.Debug.Printf("multi[%T].RangeReader(%q) = %v", c, key, err)
		}
	}

	return nil, io.EOF
}

// TODO: Does this make sense?
func (m *multiCache) Size(ctx context.Context, key string) (int64, error) {
	for _, c := range m.caches {
		sz, err := c.Size(ctx, key)
		if err == nil {
			return sz, nil
		} else {
			logs.Debug.Printf("multi[%T].Size(%q) = %v", c, key, err)
		}
	}

	return -1, io.EOF
}

type multiWriter struct {
	writers []io.WriteCloser
}

func (t *multiWriter) Write(p []byte) (n int, err error) {
	for _, w := range t.writers {
		n, err = w.Write(p)
		if err != nil {
			return
		}
		if n != len(p) {
			err = io.ErrShortWrite
			return
		}
	}
	return len(p), nil
}

func (t *multiWriter) Close() error {
	errs := []error{}
	for _, w := range t.writers {
		if err := w.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return Join(errs...)
}

func MultiWriter(writers ...io.WriteCloser) io.WriteCloser {
	allWriters := make([]io.WriteCloser, 0, len(writers))
	for _, w := range writers {
		if mw, ok := w.(*multiWriter); ok {
			allWriters = append(allWriters, mw.writers...)
		} else {
			allWriters = append(allWriters, w)
		}
	}
	return &multiWriter{allWriters}
}

// TODO: 1.20 errors.Join
func Join(errs ...error) error {
	n := 0
	for _, err := range errs {
		if err != nil {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	e := &joinError{
		errs: make([]error, 0, n),
	}
	for _, err := range errs {
		if err != nil {
			e.errs = append(e.errs, err)
		}
	}
	return e
}

type joinError struct {
	errs []error
}

func (e *joinError) Error() string {
	var b []byte
	for i, err := range e.errs {
		if i > 0 {
			b = append(b, '\n')
		}
		b = append(b, err.Error()...)
	}
	return string(b)
}

func (e *joinError) Unwrap() []error {
	return e.errs
}

func buildGcsCache(bucket string) (cache, error) {
	client, err := storage.NewClient(context.Background())
	if err != nil {
		return nil, err
	}
	bkt := client.Bucket(bucket)

	return &gcsCache{client, bkt}, nil
}

func buildTocCache() cache {
	mc := &memCache{
		// 50 MB * 50 = 2.5GB reserved for cache.
		maxSize:  50 * (1 << 20),
		entryCap: 50,
	}
	return mc
}

func buildIndexCache() cache {
	caches := []cache{}

	if cd := os.Getenv("CACHE_DIR"); cd != "" {
		logs.Debug.Printf("CACHE_DIR=%q", cd)
		cache := &dirCache{cd}
		caches = append(caches, cache)
	} else if cb := os.Getenv("CACHE_BUCKET"); cb != "" {
		logs.Debug.Printf("CACHE_BUCKET=%q", cb)
		if cache, err := buildGcsCache(cb); err != nil {
			logs.Debug.Printf("buildGcsCache(): %v", err)
		} else {
			caches = append(caches, cache)
		}
	}
	return &multiCache{caches}
}
