package explore

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/logs"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/name"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/remote"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/types"
	httpserve "github.com/jonjohnsonjr/dagdotdev/pkg/forks/http"
	"github.com/jonjohnsonjr/dagdotdev/pkg/soci"
)

const spanSize = 1 << 22

// tryNewIndex serves a layer's tar contents while building (or piggy-backing
// on) an index for it. The first concurrent request for a given key drives
// indexing via the StreamingIndex returned from NewStreaming; subsequent
// concurrent requests for the same key skip the indexing setup and stream
// from their own blob copy — the user gets to browse files as they're
// loaded without paying the full peek/Writer setup again.
//
// FIXME: the inflight check-then-insert is racy. Two requests can both
// observe inflight=false and both run NewStreaming, so under contention we
// occasionally do 2× indexing work for the same key (correct output, just
// wasted CPU + a redundant cache write). A real fix would pre-claim the
// slot under the lock with a "ready" channel that the producer closes once
// the indexer is set; left for a follow-up since the cost is bounded.
func (h *handler) tryNewIndex(w http.ResponseWriter, r *http.Request, dig name.Digest, ref string, blob *sizeBlob) (string, io.ReadCloser, io.ReadCloser, error) {
	key := soci.IndexKey(dig.Identifier(), 0)
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
		si, pr, tpr, err = h.indexes.NewStreaming(r.Context(), dig.Identifier(), blob, mt)
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

	fs := h.newLayerFS(tr, blob.size, ref, dig.String(), kind, types.MediaType(mt))

	if !inflight {
		blob.h = h
		blob.w = w
		blob.total = loadingBarSize(dig.String())
	}

	httpserve.FileServer(fs).ServeHTTP(w, r)

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

func (h *handler) createFs(w http.ResponseWriter, r *http.Request, ref string, dig name.Digest, index soci.Index, size int64, mt types.MediaType, urls []string, opts []remote.Option) (*soci.SociFS, error) {
	if opts == nil {
		opts = h.remoteOptions(w, r, dig.Context().Name())
	}
	opts = append(opts, remote.WithSize(size))

	cachedStr := ""
	if len(urls) > 0 {
		cachedStr = urls[0]
	}
	blob := remote.LazyBlob(dig, cachedStr, nil, opts...)

	// We never saw a non-nil Body, we can do the range.
	prefix := strings.TrimPrefix(ref, "/")
	fs := soci.FS(index, blob, prefix, dig.String(), respTooBig, mt, renderHeader)
	return fs, nil
}
