package apk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/v1/types"
	httpserve "github.com/jonjohnsonjr/dagdotdev/internal/forks/http"
	"github.com/jonjohnsonjr/dagdotdev/internal/soci"
)

// 5 MB.
const threshold = (1 << 20) * 5
const spanSize = 1 << 22

func indexKey(prefix string, idx int) string {
	if _, digest, ok := strings.Cut(prefix, "@"); ok {
		return fmt.Sprintf("%s.%d", digest, idx)
	}
	return fmt.Sprintf("%s.%d", prefix, idx)
}

// Attempt to create a new index. If we fail, both readclosers will be nil.
// TODO: Dedupe with createIndex.
func (h *handler) tryNewIndex(w http.ResponseWriter, r *http.Request, prefix, ref string, blob *sizeBlob) (string, io.ReadCloser, io.ReadCloser, error) {
	key := "missing"

	if _, digest, ok := strings.Cut(ref, "@"); ok {
		key = indexKey(digest, 0)
	}

	cw, err := h.indexCache.Writer(r.Context(), key)
	if err != nil {
		return "", nil, nil, fmt.Errorf("indexCache.Writer: %w", err)
	}
	defer cw.Close()

	// TODO: Plumb this down into NewIndexer so we don't create it until we need to.

	mt := r.URL.Query().Get("mt")
	indexer, kind, pr, tpr, err := soci.NewIndexer(blob, cw, spanSize, mt)
	if indexer == nil {
		logs.Debug.Printf("nil indexer")
		return kind, pr, tpr, err
	}

	// Render FS the old way while generating the index.
	fs := h.newLayerFS(indexer, blob.size, prefix, ref, indexer.Type(), types.MediaType(mt))

	logs.Debug.Printf("r.URL.Path=%q", r.URL.Path)
	if strings.HasSuffix(r.URL.Path, "APKINDEX") {
		// filename := strings.TrimPrefix(r.URL.Path, "/")
		filename := r.URL.Path
		log.Printf("opening %q", filename)
		rc, err := fs.Open(filename)
		if err != nil {
			return kind, nil, nil, fmt.Errorf("open(%q): %w", filename, err)
		}
		defer rc.Close()

		if err := h.renderIndex(w, r, rc, ref); err != nil {
			return kind, nil, nil, fmt.Errorf("renderIndex(%q): %w", filename, err)
		}
	} else {
		httpserve.FileServer(fs).ServeHTTP(w, r)
	}

	for {
		// Make sure we hit the end.
		_, err := indexer.Next()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return "", nil, nil, fmt.Errorf("indexer.Next: %w", err)
		}
	}

	toc, err := indexer.TOC()
	if err != nil {
		return kind, nil, nil, err
	}
	if h.tocCache != nil {
		if err := h.tocCache.Put(r.Context(), key, toc); err != nil {
			logs.Debug.Printf("cache.Put(%q) = %v", key, err)
		}
	}

	logs.Debug.Printf("index size: %d", indexer.Size())

	return kind, nil, nil, nil
}

// Returns nil index if it's incomplete.
func (h *handler) getIndex(ctx context.Context, prefix string) (soci.Index, error) {
	if h.indexCache == nil {
		return nil, nil
	}
	index, err := h.getIndexN(ctx, prefix, 0)
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

func (h *handler) getIndexN(ctx context.Context, prefix string, idx int) (index soci.Index, err error) {
	key := indexKey(prefix, idx)
	bs := &cacheSeeker{h.indexCache, key}

	var (
		toc  *soci.TOC
		size int64
	)
	// Avoid calling cache.Size if we can.
	if h.tocCache != nil {
		toc, err = h.tocCache.Get(ctx, key)
		if err != nil {
			logs.Debug.Printf("cache.Get(%q) = %v", key, err)
			defer func() {
				if err == nil {
					if err := h.tocCache.Put(ctx, key, index.TOC()); err != nil {
						logs.Debug.Printf("cache.Put(%q) = %v", key, err)
					}
				}
			}()
		} else {
			size = toc.Size
			logs.Debug.Printf("cache.Get(%q) = hit", key)
		}
	}

	// Handle in-memory index under a certain size.
	if size == 0 {
		size, err = h.indexCache.Size(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("indexCache.Size: %w", err)
		}
	}
	if size <= threshold {
		return soci.NewIndex(bs, toc, nil)
	}

	// Index is too big to hold in memory, fetch or create an index of the index.
	sub, err := h.getIndexN(ctx, prefix, idx+1)
	if err != nil {
		logs.Debug.Printf("getIndexN(%q, %d) = %v", prefix, idx+1, err)
		rc, err := h.indexCache.Reader(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("indexCache.Reader: %w", err)
		}
		sub, err = h.createIndex(ctx, rc, size, prefix, idx+1, "application/tar+gzip")
		if err != nil {
			return nil, fmt.Errorf("createIndex(%q, %d): %w", prefix, idx+1, err)
		}
		if sub == nil {
			return nil, fmt.Errorf("createIndex returned nil, not a tar.gz file")
		}
	}

	return soci.NewIndex(bs, toc, sub)
}

func (h *handler) createIndex(ctx context.Context, rc io.ReadCloser, size int64, prefix string, idx int, mediaType string) (soci.Index, error) {
	key := indexKey(prefix, idx)
	cw, err := h.indexCache.Writer(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("indexCache.Writer: %w", err)
	}
	defer cw.Close()

	// TODO: Better?
	indexer, _, _, _, err := soci.NewIndexer(rc, cw, spanSize, mediaType)
	if err != nil {
		return nil, fmt.Errorf("TODO: don't return this error: %w", err)
	}
	if indexer == nil {
		return nil, nil
	}
	for {
		// Make sure we hit the end.
		_, err := indexer.Next()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("indexer.Next: %w", err)
		}
	}

	toc, err := indexer.TOC()
	if err != nil {
		return nil, fmt.Errorf("TOC: %w", err)
	}
	if h.tocCache != nil {
		if err := h.tocCache.Put(ctx, key, toc); err != nil {
			logs.Debug.Printf("cache.Put(%q) = %v", key, err)
		}
	}
	logs.Debug.Printf("index size: %d", indexer.Size())

	if err := cw.Close(); err != nil {
		return nil, fmt.Errorf("cw.Close: %w", err)
	}

	return h.getIndexN(ctx, prefix, idx)
}
