package blobcache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/jonjohnsonjr/dagdotdev/pkg/soci"
)

func TestMem_GetMissReturnsEOF(t *testing.T) {
	m := NewMem(1<<20, 4)
	_, err := m.Get(context.Background(), "missing")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Get on miss = %v, want io.EOF", err)
	}
}

func TestMem_PutGetRoundtrip(t *testing.T) {
	m := NewMem(1<<20, 4)
	want := &soci.TOC{Type: "tar+gzip", Size: 1234}
	if err := m.Put(context.Background(), "k1", want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := m.Get(context.Background(), "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != want {
		t.Fatalf("Get returned different *TOC than Put stored")
	}
}

func TestMem_PutOversizedSilentlyDrops(t *testing.T) {
	m := NewMem(100, 4)
	big := &soci.TOC{Size: 200}
	if err := m.Put(context.Background(), "k1", big); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := m.Get(context.Background(), "k1"); !errors.Is(err, io.EOF) {
		t.Fatalf("oversized TOC should not be cached, got err=%v", err)
	}
}

func TestMem_LRUEviction(t *testing.T) {
	m := NewMem(1<<20, 2)
	ctx := context.Background()
	a := &soci.TOC{Size: 1}
	b := &soci.TOC{Size: 2}
	c := &soci.TOC{Size: 3}

	if err := m.Put(ctx, "a", a); err != nil {
		t.Fatal(err)
	}
	if err := m.Put(ctx, "b", b); err != nil {
		t.Fatal(err)
	}
	// Touch "a" so it's most-recent; "b" should be evicted on next Put.
	if _, err := m.Get(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := m.Put(ctx, "c", c); err != nil {
		t.Fatal(err)
	}

	if _, err := m.Get(ctx, "a"); err != nil {
		t.Errorf("recently-touched 'a' was evicted: %v", err)
	}
	if _, err := m.Get(ctx, "c"); err != nil {
		t.Errorf("just-inserted 'c' is missing: %v", err)
	}
	if _, err := m.Get(ctx, "b"); !errors.Is(err, io.EOF) {
		t.Errorf("least-recent 'b' should be evicted, got err=%v", err)
	}
}

// fakeStore is an in-memory soci.BlobStore for Multi tests.
type fakeStore struct {
	data    map[string][]byte
	writeCh chan string // optional: each Writer-on-Close key is sent here
}

func newFakeStore() *fakeStore {
	return &fakeStore{data: map[string][]byte{}}
}

func (f *fakeStore) Size(ctx context.Context, key string) (int64, error) {
	b, ok := f.data[key]
	if !ok {
		return -1, io.EOF
	}
	return int64(len(b)), nil
}

func (f *fakeStore) Reader(ctx context.Context, key string) (io.ReadCloser, error) {
	b, ok := f.data[key]
	if !ok {
		return nil, io.EOF
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (f *fakeStore) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	return &fakeWriter{store: f, key: key}, nil
}

func (f *fakeStore) RangeReader(ctx context.Context, key string, off, length int64) (io.ReadCloser, error) {
	b, ok := f.data[key]
	if !ok {
		return nil, io.EOF
	}
	if length == -1 {
		return io.NopCloser(bytes.NewReader(b[off:])), nil
	}
	return io.NopCloser(bytes.NewReader(b[off : off+length])), nil
}

type fakeWriter struct {
	store *fakeStore
	key   string
	buf   bytes.Buffer
}

func (w *fakeWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *fakeWriter) Close() error {
	w.store.data[w.key] = w.buf.Bytes()
	if w.store.writeCh != nil {
		w.store.writeCh <- w.key
	}
	return nil
}

func TestMulti_ReaderFallthroughOnMiss(t *testing.T) {
	first := newFakeStore() // empty
	second := newFakeStore()
	second.data["k"] = []byte("hello")

	m := NewMulti(first, second)
	rc, err := m.Reader(context.Background(), "k")
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "hello" {
		t.Fatalf("Reader = %q, want %q", got, "hello")
	}
}

func TestMulti_ReaderAllMissReturnsEOF(t *testing.T) {
	m := NewMulti(newFakeStore(), newFakeStore())
	if _, err := m.Reader(context.Background(), "k"); !errors.Is(err, io.EOF) {
		t.Fatalf("Reader on all-miss = %v, want io.EOF", err)
	}
}

func TestMulti_WriterFanout(t *testing.T) {
	a := newFakeStore()
	b := newFakeStore()

	m := NewMulti(a, b)
	w, err := m.Writer(context.Background(), "k")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "payload"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	for name, store := range map[string]*fakeStore{"a": a, "b": b} {
		got, ok := store.data["k"]
		if !ok {
			t.Errorf("store %s did not receive write", name)
			continue
		}
		if string(got) != "payload" {
			t.Errorf("store %s got %q, want %q", name, got, "payload")
		}
	}
}

func TestMulti_RangeReaderOffsetLength(t *testing.T) {
	s := newFakeStore()
	s.data["k"] = []byte("0123456789")
	m := NewMulti(s)

	rc, err := m.RangeReader(context.Background(), "k", 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "3456" {
		t.Fatalf("RangeReader(3,4) = %q, want %q", got, "3456")
	}
}

func TestDir_WriterReaderRoundtrip(t *testing.T) {
	d := NewDir(t.TempDir())
	ctx := context.Background()

	w, err := d.Writer(ctx, "blob1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "hello world"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	sz, err := d.Size(ctx, "blob1")
	if err != nil {
		t.Fatal(err)
	}
	if sz != int64(len("hello world")) {
		t.Errorf("Size = %d, want %d", sz, len("hello world"))
	}

	rc, err := d.Reader(ctx, "blob1")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "hello world" {
		t.Fatalf("Reader = %q, want %q", got, "hello world")
	}
}

func TestDir_RangeReader(t *testing.T) {
	d := NewDir(t.TempDir())
	ctx := context.Background()
	w, _ := d.Writer(ctx, "k")
	io.WriteString(w, "0123456789")
	w.Close()

	rc, err := d.RangeReader(ctx, "k", 2, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "23456" {
		t.Fatalf("RangeReader(2,5) = %q, want %q", got, "23456")
	}
}
