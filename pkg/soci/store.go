package soci

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/logs"
)

// BlobStore is a keyed byte store. Implementations may be backed by GCS, the
// local filesystem, in-memory maps, etc. RangeReader length=-1 means "to end".
type BlobStore interface {
	Size(ctx context.Context, key string) (int64, error)
	Reader(ctx context.Context, key string) (io.ReadCloser, error)
	Writer(ctx context.Context, key string) (io.WriteCloser, error)
	RangeReader(ctx context.Context, key string, off, length int64) (io.ReadCloser, error)
}

// TOCCache caches parsed TOCs for fast lookup. Optional companion to a
// BlobStore — typically backed by an in-memory LRU so we can skip
// deserializing the TOC from the underlying blob on every request.
type TOCCache interface {
	Get(ctx context.Context, key string) (*TOC, error)
	Put(ctx context.Context, key string, toc *TOC) error
}

// IndexStore resolves and creates indexes backed by a BlobStore, with an
// optional TOCCache for fast metadata lookups. It owns the threshold logic
// for index-of-index recursion: if an index's serialized size exceeds
// Threshold, IndexStore builds a higher-level index over it so the leaf
// never has to be loaded into memory in full.
type IndexStore struct {
	Blobs     BlobStore
	TOCs      TOCCache // optional
	Threshold int64    // bytes; if 0, defaults to 5 MB
	SpanSize  int64    // gzip span size; if 0, defaults to 4 MB
}

const (
	defaultThreshold = 5 << 20
	defaultSpanSize  = 4 << 20
)

func (s *IndexStore) threshold() int64 {
	if s.Threshold == 0 {
		return defaultThreshold
	}
	return s.Threshold
}

func (s *IndexStore) spanSize() int64 {
	if s.SpanSize == 0 {
		return defaultSpanSize
	}
	return s.SpanSize
}

// IndexKey returns the per-level key used to address an index in a BlobStore.
// Level 0 is the leaf index for prefix; level N>0 is the index-of-index built
// over level N-1 when the lower level exceeds Threshold.
func IndexKey(prefix string, level int) string {
	return fmt.Sprintf("%s.%d", prefix, level)
}

// keyedSeeker adapts a BlobStore + key into a BlobSeeker, so callers can
// use the per-key view that the Index / SociFS APIs expect.
type keyedSeeker struct {
	bs  BlobStore
	key string
}

// KeyedSeeker returns a BlobSeeker that range-reads bs at the given key.
func KeyedSeeker(bs BlobStore, key string) BlobSeeker {
	return &keyedSeeker{bs: bs, key: key}
}

func (k *keyedSeeker) Reader(ctx context.Context, off, end int64) (io.ReadCloser, error) {
	return k.bs.RangeReader(ctx, k.key, off, end-off)
}

// Get returns the cached index for prefix, recursively walking up to
// higher-level indexes-of-indexes when the leaf exceeds Threshold. Returns
// (nil, nil) if the index is missing or its TOC isn't ready yet.
func (s *IndexStore) Get(ctx context.Context, prefix string) (Index, error) {
	if s.Blobs == nil {
		return nil, nil
	}
	index, err := s.getN(ctx, prefix, 0)
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// TODO: Remove the need for this.
	if index.TOC() == nil {
		return nil, nil
	}
	return index, nil
}

// Create builds a fresh top-level index for prefix from rc (which is the
// raw blob to index — typically a tar.gz layer). The resulting index and
// its TOC are written to Blobs / TOCs under prefix.
func (s *IndexStore) Create(ctx context.Context, prefix string, rc io.ReadCloser, mediaType string) (Index, error) {
	return s.createN(ctx, rc, prefix, 0, mediaType)
}

func (s *IndexStore) getN(ctx context.Context, prefix string, level int) (index Index, err error) {
	key := IndexKey(prefix, level)
	bs := KeyedSeeker(s.Blobs, key)

	var (
		toc  *TOC
		size int64
	)
	// Avoid calling Blobs.Size if we can.
	if s.TOCs != nil {
		toc, err = s.TOCs.Get(ctx, key)
		if err != nil {
			logs.Debug.Printf("cache.Get(%q) = %v", key, err)
			defer func() {
				if err == nil {
					if err := s.TOCs.Put(ctx, key, index.TOC()); err != nil {
						logs.Debug.Printf("cache.Put(%q) = %v", key, err)
					}
				}
			}()
		} else {
			size = toc.Size
			logs.Debug.Printf("cache.Get(%q) = hit", key)
		}
	}

	if size == 0 {
		size, err = s.Blobs.Size(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("Blobs.Size: %w", err)
		}
	}
	if size <= s.threshold() {
		return NewIndex(bs, toc, nil)
	}

	// Index is too big to hold in memory; fetch or create an index-of-index.
	sub, err := s.getN(ctx, prefix, level+1)
	if err != nil {
		logs.Debug.Printf("getN(%q, %d) = %v", prefix, level+1, err)
		rc, err := s.Blobs.Reader(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("Blobs.Reader: %w", err)
		}
		sub, err = s.createN(ctx, rc, prefix, level+1, "application/tar+gzip")
		if err != nil {
			return nil, fmt.Errorf("createN(%q, %d): %w", prefix, level+1, err)
		}
		if sub == nil {
			return nil, fmt.Errorf("createN returned nil, not a tar.gz file")
		}
	}

	return NewIndex(bs, toc, sub)
}

func (s *IndexStore) createN(ctx context.Context, rc io.ReadCloser, prefix string, level int, mediaType string) (Index, error) {
	key := IndexKey(prefix, level)
	cw, err := s.Blobs.Writer(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("Blobs.Writer: %w", err)
	}
	defer cw.Close()

	indexer, _, _, _, err := NewIndexer(rc, cw, s.spanSize(), mediaType)
	if indexer == nil {
		// NewIndexer returns nil indexer for non-archive inputs and on Peek
		// failures (typically too-short streams). Surface as (nil, nil) so
		// callers can fall back to serving the blob as a non-filesystem.
		if err != nil {
			logs.Debug.Printf("NewIndexer(%q): %v", key, err)
		}
		return nil, nil
	}
	for {
		if _, err := indexer.Next(); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("indexer.Next: %w", err)
		}
	}

	toc, err := indexer.TOC()
	if err != nil {
		return nil, fmt.Errorf("TOC: %w", err)
	}
	if s.TOCs != nil {
		if err := s.TOCs.Put(ctx, key, toc); err != nil {
			logs.Debug.Printf("cache.Put(%q) = %v", key, err)
		}
	}
	logs.Debug.Printf("index size: %d", indexer.Size())

	if err := cw.Close(); err != nil {
		return nil, fmt.Errorf("cw.Close: %w", err)
	}

	return s.getN(ctx, prefix, level)
}
