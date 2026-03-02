package git

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
)

type packCache interface {
	GetIndex(ctx context.Context, key string) (*PackIndex, error)
	PutIndex(ctx context.Context, key string, idx *PackIndex) error
	GetPack(ctx context.Context, key string) ([]byte, error)
	PutPack(ctx context.Context, key string, data []byte) error
	RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error)
}

func cacheKey(repoURL string) string {
	h := sha256.Sum256([]byte(repoURL))
	return fmt.Sprintf("%x", h[:16])
}

// gcsPackCache stores packs and indexes in GCS.
type gcsPackCache struct {
	bucket *storage.BucketHandle
}

func (g *gcsPackCache) packPath(key string) string {
	return fmt.Sprintf("pack/%s/pack.bin", key)
}

func (g *gcsPackCache) indexPath(key string) string {
	return fmt.Sprintf("pack/%s/index.json.gz", key)
}

func (g *gcsPackCache) GetIndex(ctx context.Context, key string) (*PackIndex, error) {
	rc, err := g.bucket.Object(g.indexPath(key)).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	zr, err := gzip.NewReader(rc)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	idx := &PackIndex{}
	if err := json.NewDecoder(zr).Decode(idx); err != nil {
		return nil, err
	}
	return idx, nil
}

func (g *gcsPackCache) PutIndex(ctx context.Context, key string, idx *PackIndex) error {
	w := g.bucket.Object(g.indexPath(key)).NewWriter(ctx)
	zw, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(zw).Encode(idx); err != nil {
		zw.Close()
		w.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

func (g *gcsPackCache) GetPack(ctx context.Context, key string) ([]byte, error) {
	rc, err := g.bucket.Object(g.packPath(key)).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (g *gcsPackCache) PutPack(ctx context.Context, key string, data []byte) error {
	w := g.bucket.Object(g.packPath(key)).NewWriter(ctx)
	if _, err := w.Write(data); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

func (g *gcsPackCache) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	return g.bucket.Object(g.packPath(key)).NewRangeReader(ctx, offset, length)
}

// dirPackCache stores packs and indexes in a local directory.
type dirPackCache struct {
	dir string
}

func (d *dirPackCache) path(key, name string) string {
	return filepath.Join(d.dir, "pack", key, name)
}

func (d *dirPackCache) ensureDir(key string) error {
	return os.MkdirAll(filepath.Join(d.dir, "pack", key), 0755)
}

func (d *dirPackCache) GetIndex(ctx context.Context, key string) (*PackIndex, error) {
	f, err := os.Open(d.path(key, "index.json.gz"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	idx := &PackIndex{}
	if err := json.NewDecoder(zr).Decode(idx); err != nil {
		return nil, err
	}
	return idx, nil
}

func (d *dirPackCache) PutIndex(ctx context.Context, key string, idx *PackIndex) error {
	if err := d.ensureDir(key); err != nil {
		return err
	}
	f, err := os.Create(d.path(key, "index.json.gz"))
	if err != nil {
		return err
	}
	defer f.Close()
	zw, err := gzip.NewWriterLevel(f, gzip.BestSpeed)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(zw).Encode(idx); err != nil {
		zw.Close()
		return err
	}
	return zw.Close()
}

func (d *dirPackCache) GetPack(ctx context.Context, key string) ([]byte, error) {
	return os.ReadFile(d.path(key, "pack.bin"))
}

func (d *dirPackCache) PutPack(ctx context.Context, key string, data []byte) error {
	if err := d.ensureDir(key); err != nil {
		return err
	}
	return os.WriteFile(d.path(key, "pack.bin"), data, 0644)
}

func (d *dirPackCache) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	f, err := os.Open(d.path(key, "pack.bin"))
	if err != nil {
		return nil, err
	}
	return io.NopCloser(io.NewSectionReader(f, offset, length)), nil
}

// memPackIndex is an in-memory LRU of parsed PackIndex structs.
type memPackIndex struct {
	mu      sync.Mutex
	cap     int
	entries map[string]*memIndexEntry
}

type memIndexEntry struct {
	idx    *PackIndex
	access time.Time
}

func (m *memPackIndex) Get(key string) *PackIndex {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[key]; ok {
		e.access = time.Now()
		return e.idx
	}
	return nil
}

func (m *memPackIndex) Put(key string, idx *PackIndex) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = make(map[string]*memIndexEntry)
	}
	if len(m.entries) >= m.cap {
		var oldest string
		var oldestTime time.Time
		for k, e := range m.entries {
			if oldest == "" || e.access.Before(oldestTime) {
				oldest = k
				oldestTime = e.access
			}
		}
		delete(m.entries, oldest)
	}
	m.entries[key] = &memIndexEntry{idx: idx, access: time.Now()}
}

func buildPackCache() packCache {
	if cd := os.Getenv("CACHE_DIR"); cd != "" {
		log.Printf("pack cache: dir=%s", cd)
		return &dirPackCache{dir: cd}
	}
	if cb := os.Getenv("CACHE_BUCKET"); cb != "" {
		log.Printf("pack cache: bucket=%s", cb)
		client, err := storage.NewClient(context.Background())
		if err != nil {
			log.Printf("pack cache: gcs error: %v", err)
			return &noopPackCache{}
		}
		bkt := client.Bucket(strings.TrimPrefix(cb, "gs://"))
		return &gcsPackCache{bucket: bkt}
	}
	return &noopPackCache{}
}

// noopPackCache is used when no cache backend is configured.
type noopPackCache struct{}

func (n *noopPackCache) GetIndex(ctx context.Context, key string) (*PackIndex, error) {
	return nil, fmt.Errorf("no cache")
}
func (n *noopPackCache) PutIndex(ctx context.Context, key string, idx *PackIndex) error {
	return nil
}
func (n *noopPackCache) GetPack(ctx context.Context, key string) ([]byte, error) {
	return nil, fmt.Errorf("no cache")
}
func (n *noopPackCache) PutPack(ctx context.Context, key string, data []byte) error {
	return nil
}
func (n *noopPackCache) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	return nil, fmt.Errorf("no cache")
}

// tieredPackCache wraps a persistent cache with an in-memory LRU for indexes.
type tieredPackCache struct {
	mem  *memPackIndex
	back packCache
}

func (t *tieredPackCache) GetIndex(ctx context.Context, key string) (*PackIndex, error) {
	if idx := t.mem.Get(key); idx != nil {
		return idx, nil
	}
	idx, err := t.back.GetIndex(ctx, key)
	if err != nil {
		return nil, err
	}
	t.mem.Put(key, idx)
	return idx, nil
}

func (t *tieredPackCache) PutIndex(ctx context.Context, key string, idx *PackIndex) error {
	t.mem.Put(key, idx)
	return t.back.PutIndex(ctx, key, idx)
}

func (t *tieredPackCache) GetPack(ctx context.Context, key string) ([]byte, error) {
	return t.back.GetPack(ctx, key)
}

func (t *tieredPackCache) PutPack(ctx context.Context, key string, data []byte) error {
	return t.back.PutPack(ctx, key, data)
}

func (t *tieredPackCache) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	return t.back.RangeReader(ctx, key, offset, length)
}

func newPackCache() packCache {
	return &tieredPackCache{
		mem:  &memPackIndex{cap: 50},
		back: buildPackCache(),
	}
}

// memPackData holds raw packfile bytes in memory for object detail views.
type memPackData struct {
	mu   sync.Mutex
	data map[string][]byte
}

func (m *memPackData) Get(key string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data[key]
}

func (m *memPackData) Put(key string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	m.data[key] = data
}

