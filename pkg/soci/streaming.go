package soci

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/logs"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/klauspost/compress/zstd"
)

// TarReader is the read side of a tar archive: byte reads plus Next() to
// advance to the next header.
type TarReader interface {
	io.Reader
	Next() (*tar.Header, error)
}

// OpenTar wraps rc as a TarReader appropriate for kind, where kind is one of
// the values returned by Indexer.Type() ("tar", "tar+gzip", "tar+zstd").
// Returns nil for unknown kinds; the caller should fall back to non-archive
// serving.
func OpenTar(rc io.Reader, kind string) (TarReader, error) {
	switch kind {
	case "tar":
		return tar.NewReader(rc), nil
	case "tar+gzip":
		zr, err := gzip.NewReader(rc)
		if err != nil {
			return nil, fmt.Errorf("gzip.NewReader: %w", err)
		}
		return tar.NewReader(zr), nil
	case "tar+zstd":
		zr, err := zstd.NewReader(rc)
		if err != nil {
			return nil, fmt.Errorf("zstd.NewReader: %w", err)
		}
		return tar.NewReader(zr), nil
	default:
		return nil, nil
	}
}

// Streaming is an in-flight tar-reading + indexing session started by
// IndexStore.NewStreaming. Callers consume TR (the tar reader over the live
// blob, backed by Indexer when non-nil) to render archive contents, then
// call Done to drain any remaining entries and persist the TOC.
//
// On non-archive inputs, NewStreaming returns a Streaming whose Indexer and
// TR are nil; callers should fall back to non-indexed serving and skip Done.
type Streaming struct {
	Kind    string
	TR      TarReader
	Indexer *Indexer

	s      *IndexStore
	prefix string
	cw     io.WriteCloser
}

// NewStreaming begins building a level-0 index for prefix from blob, writing
// the index to s.Blobs as it goes. TR on the returned Streaming reads from
// the same indexer, so consuming TR drives indexing forward.
//
// If blob is not a recognizable archive, the returned Streaming has Indexer
// and TR nil; the original and unwrapped readers from NewIndexer are
// returned so the caller can serve them as a non-archive blob.
func (s *IndexStore) NewStreaming(ctx context.Context, prefix string, blob io.ReadCloser, mediaType string) (*Streaming, io.ReadCloser, io.ReadCloser, error) {
	key := IndexKey(prefix, 0)
	cw, err := s.Blobs.Writer(ctx, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Blobs.Writer: %w", err)
	}

	indexer, _, pr, tpr, err := NewIndexer(blob, cw, s.spanSize(), mediaType)
	if indexer == nil {
		// Non-archive or peek failure. Close the writer; we have nothing to
		// commit. (Note: the underlying Dir/GCS writers commit-on-Close, so
		// we may leave a 0-byte poison-pill at this key. Tracked as the
		// partial-write bug in the refactor audit.)
		cw.Close()
		return &Streaming{}, pr, tpr, err
	}

	return &Streaming{
		Kind:    indexer.Type(),
		TR:      indexer,
		Indexer: indexer,
		s:       s,
		prefix:  prefix,
		cw:      cw,
	}, nil, nil, nil
}

// LiveIndex returns a soci.Index backed by this streaming session's live
// TOC plus the given BlobSeeker (which must address the source archive).
// Concurrent readers can use the returned Index to browse files that have
// already been indexed; files not yet seen return fs.ErrNotExist.
//
// Returns nil if the Streaming is for a non-archive (Indexer == nil).
func (si *Streaming) LiveIndex(bs BlobSeeker) *LiveIndex {
	if si.Indexer == nil {
		return nil
	}
	return NewLiveIndex(si.Indexer.LiveTOC(), bs)
}

// Done drains any tar entries the caller didn't consume, then persists the
// TOC to s.TOCs (if configured) and closes the index writer. Safe to call
// on a Streaming with nil Indexer (returns nil immediately).
//
// On drain or TOC errors, Done still closes the writer — meaning a partial
// index blob ends up at the canonical cache key. See audit notes; fix is
// pending an explicit Commit/Abort protocol on BlobStore.Writer.
func (si *Streaming) Done(ctx context.Context) error {
	if si.Indexer == nil {
		return nil
	}
	defer si.cw.Close()

	for {
		if _, err := si.Indexer.Next(); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("indexer.Next: %w", err)
		}
	}

	toc, err := si.Indexer.TOC()
	if err != nil {
		return fmt.Errorf("TOC: %w", err)
	}
	if si.s.TOCs != nil {
		if err := si.s.TOCs.Put(ctx, IndexKey(si.prefix, 0), toc); err != nil {
			logs.Debug.Printf("cache.Put: %v", err)
		}
	}
	logs.Debug.Printf("index size: %d", si.Indexer.Size())
	return nil
}
