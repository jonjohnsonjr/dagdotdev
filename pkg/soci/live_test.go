package soci

import (
	"errors"
	"io/fs"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/compress/flate"
)

func TestLiveTOC_AppendAndLocate(t *testing.T) {
	l := NewLiveTOC(&TOC{Type: "tar+gzip"})
	l.AppendFile(TOCFile{Name: "a.txt", Size: 10, Offset: 100})
	l.AppendFile(TOCFile{Name: "b.txt", Size: 20, Offset: 200})

	got, ok := l.Locate("a.txt")
	if !ok {
		t.Fatal("Locate a.txt: not found")
	}
	if got.Size != 10 || got.Offset != 100 {
		t.Errorf("Locate(a.txt) = %+v, want size=10 offset=100", got)
	}

	if _, ok := l.Locate("missing"); ok {
		t.Error("Locate(missing) should not be found")
	}
}

func TestLiveTOC_SnapshotIsStable(t *testing.T) {
	l := NewLiveTOC(&TOC{Type: "tar"})
	l.AppendFile(TOCFile{Name: "first"})
	snap := l.Snapshot()
	if len(snap.Files) != 1 {
		t.Fatalf("snapshot Files = %d, want 1", len(snap.Files))
	}

	// Mutate the live TOC; snapshot should not change.
	l.AppendFile(TOCFile{Name: "second"})
	if len(snap.Files) != 1 {
		t.Errorf("snapshot mutated after later Append; got %d files", len(snap.Files))
	}

	snap2 := l.Snapshot()
	if len(snap2.Files) != 2 {
		t.Errorf("second snapshot = %d files, want 2", len(snap2.Files))
	}
}

func TestLiveTOC_ConcurrentAppendsAndReads(t *testing.T) {
	l := NewLiveTOC(&TOC{})
	const N = 1000

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			l.AppendFile(TOCFile{Name: "f", Offset: int64(i)})
		}
		l.MarkDone(nil)
	}()

	var snapshotsTaken atomic.Int64
	go func() {
		defer wg.Done()
		for !l.Done() {
			_ = l.Snapshot()
			snapshotsTaken.Add(1)
		}
		// One more after Done to verify post-done reads work.
		_ = l.Snapshot()
	}()

	wg.Wait()

	final := l.Snapshot()
	if len(final.Files) != N {
		t.Errorf("final Files = %d, want %d", len(final.Files), N)
	}
	if snapshotsTaken.Load() == 0 {
		t.Error("reader took zero snapshots — race-test isn't exercising concurrency")
	}
	if !l.Done() {
		t.Error("expected Done() true after MarkDone")
	}
}

func TestLiveTOC_DictRoundtrip(t *testing.T) {
	l := NewLiveTOC(&TOC{})
	cp := &flate.Checkpoint{}
	l.AppendCheckpoint(cp, []byte("dict-bytes"))

	got, ok := l.Dict(0)
	if !ok {
		t.Fatal("Dict(0) not found")
	}
	if string(got) != "dict-bytes" {
		t.Errorf("Dict(0) = %q, want %q", got, "dict-bytes")
	}

	if _, ok := l.Dict(99); ok {
		t.Error("Dict(99) should not be found")
	}
}

func TestLiveTOC_DictNotShared(t *testing.T) {
	// Hist passed to AppendCheckpoint should be retained as a defensive
	// copy in the live dict map only if the indexer copies it before
	// passing in. We don't copy in AppendCheckpoint itself; verify behavior:
	// modifications to the *caller's* slice after Append are reflected in
	// the live dict (consistent with the contract — caller owns the bytes).
	l := NewLiveTOC(&TOC{})
	hist := []byte("aaaa")
	l.AppendCheckpoint(&flate.Checkpoint{}, hist)
	hist[0] = 'b'

	got, _ := l.Dict(0)
	if string(got) != "baaa" {
		t.Errorf("Dict(0) = %q, want %q (live slot shares storage with caller)", got, "baaa")
	}
}

func TestLiveTOC_MarkDoneError(t *testing.T) {
	l := NewLiveTOC(&TOC{})
	wantErr := errors.New("indexing failed")
	l.MarkDone(wantErr)
	if !l.Done() {
		t.Error("Done() should be true after MarkDone")
	}
	if got := l.Err(); !errors.Is(got, wantErr) {
		t.Errorf("Err() = %v, want %v", got, wantErr)
	}
}

func TestLiveIndex_LocateNotIndexedYet(t *testing.T) {
	l := NewLiveTOC(&TOC{})
	li := NewLiveIndex(l, nil)
	if _, err := li.Locate("not-yet"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Locate on missing = %v, want fs.ErrNotExist", err)
	}
}

func TestLiveIndex_LocateAfterAppend(t *testing.T) {
	l := NewLiveTOC(&TOC{Type: "tar"})
	l.AppendFile(TOCFile{Name: "etc/hosts", Size: 100, Offset: 4096})
	li := NewLiveIndex(l, nil)

	tf, err := li.Locate("etc/hosts")
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if tf.Size != 100 {
		t.Errorf("Locate Size = %d, want 100", tf.Size)
	}
}

func TestLiveIndex_TOCIncludesLiveCounts(t *testing.T) {
	l := NewLiveTOC(&TOC{Type: "tar+gzip"})
	l.UpdateCounts(1234, 5678)
	li := NewLiveIndex(l, nil)
	toc := li.TOC()
	if toc.Csize != 1234 || toc.Usize != 5678 {
		t.Errorf("TOC counts = (%d, %d), want (1234, 5678)", toc.Csize, toc.Usize)
	}
}
