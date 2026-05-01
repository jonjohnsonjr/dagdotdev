package soci

import (
	"fmt"
	"io/fs"
	"sync"

	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/compress/flate"
)

// LiveTOC is a TOC that's safe to read while the Indexer is still appending
// to it. Files and Checkpoints grow monotonically; immutable fields (Type,
// MediaType, Ssize) are set at construction. Concurrent readers obtain
// stable views via Snapshot or per-name Locate; both take an internal lock.
//
// Lifecycle: the producer (Indexer) calls AppendFile / AppendCheckpoint /
// UpdateCounts as it reads the source archive, and MarkDone on EOF or error.
// Readers can call any read method at any time, including before MarkDone.
type LiveTOC struct {
	mu    sync.RWMutex
	cond  *sync.Cond
	toc   *TOC
	dicts map[int][]byte // checkpoint index → gzip history bytes (held in memory while TOC is live)
	done  bool
	err   error
}

// NewLiveTOC returns a LiveTOC wrapping toc. Subsequent appends go through
// the LiveTOC's lock — callers must not mutate toc.Files / toc.Checkpoints
// directly after this. Immutable fields (Type, MediaType, Ssize) may still
// be read without locking.
func NewLiveTOC(toc *TOC) *LiveTOC {
	l := &LiveTOC{
		toc:   toc,
		dicts: map[int][]byte{},
	}
	l.cond = sync.NewCond(&l.mu)
	return l
}

// AppendFile records a newly-discovered tar entry.
func (l *LiveTOC) AppendFile(f TOCFile) {
	l.mu.Lock()
	l.toc.Files = append(l.toc.Files, f)
	l.cond.Broadcast()
	l.mu.Unlock()
}

// checkpointCount returns the current number of checkpoints under lock.
// Used by the indexer to derive dict filenames before AppendCheckpoint
// runs (so the filename matches the index slot the checkpoint will land in).
func (l *LiveTOC) checkpointCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.toc.Checkpoints)
}

// AppendCheckpoint records a gzip/zstd checkpoint. If hist is non-nil, it's
// retained in memory under the checkpoint's index so live readers can hand
// it back via Dict().
func (l *LiveTOC) AppendCheckpoint(c *flate.Checkpoint, hist []byte) {
	l.mu.Lock()
	idx := len(l.toc.Checkpoints)
	l.toc.Checkpoints = append(l.toc.Checkpoints, c)
	if hist != nil {
		l.dicts[idx] = hist
	}
	l.cond.Broadcast()
	l.mu.Unlock()
}

// UpdateCounts updates the live compressed/uncompressed byte counts. These
// feed TOC.Csize/Usize so concurrent readers can compute correct byte
// ranges for files within already-indexed regions.
func (l *LiveTOC) UpdateCounts(csize, usize int64) {
	l.mu.Lock()
	l.toc.Csize = csize
	l.toc.Usize = usize
	l.mu.Unlock()
}

// MarkDone signals that no further appends will occur. Subsequent Done()
// returns true. err is recorded and returned to readers via Err().
func (l *LiveTOC) MarkDone(err error) {
	l.mu.Lock()
	l.done = true
	l.err = err
	l.cond.Broadcast()
	l.mu.Unlock()
}

// Done reports whether MarkDone has been called.
func (l *LiveTOC) Done() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.done
}

// Err returns the error passed to MarkDone (if any).
func (l *LiveTOC) Err() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.err
}

// Snapshot returns a stable, consistent view of the TOC. Files and
// Checkpoints are slice-copied so later mutations on the LiveTOC don't
// affect the returned *TOC. Immutable fields (Type, etc.) are referenced
// directly.
func (l *LiveTOC) Snapshot() *TOC {
	l.mu.RLock()
	defer l.mu.RUnlock()
	snap := *l.toc
	snap.Files = append([]TOCFile(nil), l.toc.Files...)
	snap.Checkpoints = append([]*flate.Checkpoint(nil), l.toc.Checkpoints...)
	return &snap
}

// Locate returns the file with the given name if it's been indexed yet.
// Returns (zero, false) if the name isn't yet present; callers can decide
// to retry, wait, or give up based on Done().
func (l *LiveTOC) Locate(name string) (TOCFile, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, f := range l.toc.Files {
		if f.Name == name {
			return f, true
		}
	}
	return TOCFile{}, false
}

// Dict returns the retained gzip history bytes for a checkpoint index.
func (l *LiveTOC) Dict(checkpointIndex int) ([]byte, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	h, ok := l.dicts[checkpointIndex]
	return h, ok
}

// LiveIndex satisfies soci.Index against an in-progress LiveTOC and a
// BlobSeeker for the source archive. Callers can drop a LiveIndex into
// soci.FS to browse a layer that's still being indexed; files in indexed
// regions get fast random-access reads, files not yet seen return
// fs.ErrNotExist (the caller can retry once the indexer has progressed
// past them).
type LiveIndex struct {
	live *LiveTOC
	bs   BlobSeeker
}

// NewLiveIndex returns a LiveIndex backed by live (the in-progress TOC)
// and bs (the source archive, range-readable).
func NewLiveIndex(live *LiveTOC, bs BlobSeeker) *LiveIndex {
	return &LiveIndex{live: live, bs: bs}
}

// TOC returns a snapshot of the current live state. Each call allocates a
// fresh snapshot — callers should hold the result for the duration of a
// related operation rather than calling TOC() multiple times.
func (li *LiveIndex) TOC() *TOC {
	return li.live.Snapshot()
}

// Locate returns the named file if it's been indexed. Returns fs.ErrNotExist
// otherwise — distinct from "definitively not in the archive," which we
// can't know until LiveTOC.Done().
func (li *LiveIndex) Locate(name string) (*TOCFile, error) {
	f, ok := li.live.Locate(name)
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &f, nil
}

// Dict satisfies soci.Index.Dict against the live dict map. Returns nil
// for empty checkpoints (consistent with leaf.Dict). Returns an error for
// not-yet-indexed checkpoints — for archives indexed only partway through,
// reads of files past the latest checkpoint will fail here.
func (li *LiveIndex) Dict(cp *Checkpointer) ([]byte, error) {
	if cp.Checkpoint.IsEmpty() {
		return nil, nil
	}
	if hist := cp.Checkpoint.History(); hist != nil {
		return hist, nil
	}
	h, ok := li.live.Dict(cp.index)
	if !ok {
		return nil, fmt.Errorf("dict for checkpoint %d not yet indexed", cp.index)
	}
	cp.Checkpoint.SetHistory(h)
	return h, nil
}
