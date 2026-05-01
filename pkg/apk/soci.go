package apk

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/logs"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/types"
	httpserve "github.com/jonjohnsonjr/dagdotdev/pkg/forks/http"
	"github.com/jonjohnsonjr/dagdotdev/pkg/soci"
)

const spanSize = 1 << 22

// indexPrefix derives the cache prefix for ref. apk refs are typically
// "name@digest"; we key everything by the digest portion. Refs without an
// "@" fall through unchanged.
func indexPrefix(ref string) string {
	if _, digest, ok := strings.Cut(ref, "@"); ok {
		return digest
	}
	return ref
}

// Attempt to create a new index. If we fail, both readclosers will be nil.
func (h *handler) tryNewIndex(w http.ResponseWriter, r *http.Request, prefix, ref string, blob *sizeBlob) (string, io.ReadCloser, io.ReadCloser, error) {
	// Was: `key := "missing"; if @ found { key = IndexKey(digest, 0) }`. The
	// "missing" fallback caused cache-key collisions between unrelated
	// non-`@` refs (audit bug #3). Always derive a real key now.
	cachePrefix := indexPrefix(ref)
	key := soci.IndexKey(cachePrefix, 0)
	mt := r.URL.Query().Get("mt")

	var (
		tr   soci.TarReader
		si   *soci.Streaming
		kind string
	)

	h.Lock()
	inflightIdx, inflight := h.inflight[key]
	h.Unlock()

	if inflight {
		// FIXME: inflight check-then-insert is racy; under contention two
		// requests can both run NewStreaming and produce a redundant cache
		// write. Output is correct; cost is bounded extra CPU. See explore's
		// tryNewIndex for the same caveat.
		logs.Debug.Printf("inflight[%q] exists, not indexing", key)
		kind = inflightIdx.Type()
		var err error
		tr, err = soci.OpenTar(blob, kind)
		if err != nil {
			return "", nil, nil, err
		}
	} else {
		var pr, tpr io.ReadCloser
		var err error
		si, pr, tpr, err = h.indexes.NewStreaming(r.Context(), cachePrefix, blob, mt)
		if si.Indexer == nil {
			logs.Debug.Printf("nil indexer")
			return kind, pr, tpr, err
		}
		kind = si.Kind
		tr = si.TR

		h.Lock()
		h.inflight[key] = si.Indexer
		h.Unlock()
		defer func() {
			h.Lock()
			delete(h.inflight, key)
			h.Unlock()
		}()
	}

	// Render FS the old way while generating the index.
	fs := h.newLayerFS(tr, blob.size, prefix, ref, kind, types.MediaType(mt))

	// TODO: Dedupe this section with renderFS.
	logs.Debug.Printf("r.URL.Path=%q", r.URL.Path)
	if strings.HasSuffix(r.URL.Path, "APKINDEX") {
		filename := r.URL.Path
		open := func() (io.ReadCloser, error) {
			log.Printf("opening %q", filename)
			return fs.Open(filename)
		}

		if err := h.renderIndex(w, r, open, ref); err != nil {
			return kind, nil, nil, fmt.Errorf("renderIndex(%q): %w", filename, err)
		}
	} else if strings.HasSuffix(r.URL.Path, "/.PKGINFO") {
		filename := r.URL.Path
		log.Printf("rendering .PKGINFO: %q", filename)
		rc, err := fs.Open(filename)
		if err != nil {
			return kind, nil, nil, fmt.Errorf("open(%q): %w", filename, err)
		}
		defer rc.Close()

		if err := h.renderPkgInfo(w, r, rc, ref); err != nil {
			return kind, nil, nil, fmt.Errorf("renderPkgInfo(%q): %w", filename, err)
		}
	} else {
		if !inflight {
			blob.h = h
			blob.w = w
			blob.total = loadingBarSize(ref)
		}

		httpserve.FileServer(fs).ServeHTTP(w, r)
	}

	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	if si != nil {
		if err := si.Done(r.Context()); err != nil {
			return kind, nil, nil, fmt.Errorf("Streaming.Done: %w", err)
		}
	}

	return kind, nil, nil, nil
}

