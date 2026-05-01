package soci

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestIndexKey(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		level  int
		want   string
	}{
		{"sha256:abc", 0, "sha256:abc.0"},
		{"sha256:abc", 1, "sha256:abc.1"},
		{"foo/bar", 7, "foo/bar.7"},
	} {
		if got := IndexKey(tc.prefix, tc.level); got != tc.want {
			t.Errorf("IndexKey(%q, %d) = %q, want %q", tc.prefix, tc.level, got, tc.want)
		}
	}
}

// fakeBlobStore is an in-memory BlobStore for store_test.
type fakeBlobStore struct {
	data         map[string][]byte
	rangeReadCh  chan rangeCall
	sizeFailures map[string]error
}

type rangeCall struct {
	key      string
	off, end int64 // end here is the length param passed to RangeReader (i.e. end-off)
}

func newFakeBlobStore() *fakeBlobStore { return &fakeBlobStore{data: map[string][]byte{}} }

func (f *fakeBlobStore) Size(ctx context.Context, key string) (int64, error) {
	if err, ok := f.sizeFailures[key]; ok {
		return -1, err
	}
	b, ok := f.data[key]
	if !ok {
		return -1, io.EOF
	}
	return int64(len(b)), nil
}

func (f *fakeBlobStore) Reader(ctx context.Context, key string) (io.ReadCloser, error) {
	b, ok := f.data[key]
	if !ok {
		return nil, io.EOF
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (f *fakeBlobStore) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	return nil, errors.New("Writer not used in tests")
}

func (f *fakeBlobStore) RangeReader(ctx context.Context, key string, off, length int64) (io.ReadCloser, error) {
	if f.rangeReadCh != nil {
		f.rangeReadCh <- rangeCall{key, off, length}
	}
	b, ok := f.data[key]
	if !ok {
		return nil, io.EOF
	}
	if length == -1 {
		return io.NopCloser(bytes.NewReader(b[off:])), nil
	}
	return io.NopCloser(bytes.NewReader(b[off : off+length])), nil
}

// fakeTOCs is an in-memory TOCCache for store_test.
type fakeTOCs struct {
	m map[string]*TOC
}

func (f *fakeTOCs) Get(ctx context.Context, key string) (*TOC, error) {
	if t, ok := f.m[key]; ok {
		return t, nil
	}
	return nil, io.EOF
}

func (f *fakeTOCs) Put(ctx context.Context, key string, toc *TOC) error {
	if f.m == nil {
		f.m = map[string]*TOC{}
	}
	f.m[key] = toc
	return nil
}

func TestKeyedSeeker_DelegatesToBlobStore(t *testing.T) {
	bs := newFakeBlobStore()
	bs.data["k"] = []byte("0123456789")
	bs.rangeReadCh = make(chan rangeCall, 1)

	seeker := KeyedSeeker(bs, "k")
	rc, err := seeker.Reader(context.Background(), 2, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	call := <-bs.rangeReadCh
	if call.key != "k" || call.off != 2 || call.end != 5 {
		t.Errorf("RangeReader called with (%q, %d, %d), want (k, 2, 5)", call.key, call.off, call.end)
	}
	got, _ := io.ReadAll(rc)
	if string(got) != "23456" {
		t.Errorf("Reader = %q, want %q", got, "23456")
	}
}

func TestIndexStore_Get_NilBlobsReturnsNil(t *testing.T) {
	s := &IndexStore{}
	idx, err := s.Get(context.Background(), "anything")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if idx != nil {
		t.Errorf("expected nil index when Blobs is nil")
	}
}

func TestIndexStore_Get_EOFReturnsNil(t *testing.T) {
	s := &IndexStore{Blobs: newFakeBlobStore()} // empty store, Size returns io.EOF
	idx, err := s.Get(context.Background(), "img")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if idx != nil {
		t.Errorf("expected nil index when blob is missing")
	}
}

func TestIndexStore_Get_LeafFromTOCCache(t *testing.T) {
	tocs := &fakeTOCs{m: map[string]*TOC{
		"img.0": {Size: 100, Type: "tar+gzip"},
	}}
	s := &IndexStore{Blobs: newFakeBlobStore(), TOCs: tocs, Threshold: 1 << 20}
	idx, err := s.Get(context.Background(), "img")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if idx == nil {
		t.Fatal("expected non-nil index from TOC cache hit")
	}
	if idx.TOC().Size != 100 {
		t.Errorf("Size = %d, want 100", idx.TOC().Size)
	}
}

func TestIndexStore_Get_RecursionReturnsTree(t *testing.T) {
	const threshold = int64(1 << 10)
	tocs := &fakeTOCs{m: map[string]*TOC{
		"img.0": {Size: threshold * 4, Type: "tar+gzip"}, // oversized → recurse
		"img.1": {Size: threshold / 2, Type: "tar+gzip"}, // leaf at level 1
	}}
	s := &IndexStore{Blobs: newFakeBlobStore(), TOCs: tocs, Threshold: threshold}

	idx, err := s.Get(context.Background(), "img")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if idx == nil {
		t.Fatal("expected tree index")
	}
	if idx.TOC().Size != threshold*4 {
		t.Errorf("expected level-0 TOC (Size=%d), got Size=%d", threshold*4, idx.TOC().Size)
	}
	if _, ok := idx.(*tree); !ok {
		t.Errorf("expected *tree index, got %T", idx)
	}
}

func TestIndexStore_DefaultsApplyWhenZero(t *testing.T) {
	s := &IndexStore{}
	if got := s.threshold(); got != defaultThreshold {
		t.Errorf("threshold() with zero field = %d, want default %d", got, defaultThreshold)
	}
	if got := s.spanSize(); got != defaultSpanSize {
		t.Errorf("spanSize() with zero field = %d, want default %d", got, defaultSpanSize)
	}
}

func TestIndexStore_DefaultsRespectExplicit(t *testing.T) {
	s := &IndexStore{Threshold: 42, SpanSize: 99}
	if got := s.threshold(); got != 42 {
		t.Errorf("threshold() = %d, want 42", got)
	}
	if got := s.spanSize(); got != 99 {
		t.Errorf("spanSize() = %d, want 99", got)
	}
}
