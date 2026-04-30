package explore

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/klauspost/compress/zstd"
)

// fakeRegistry is a minimal OCI distribution registry implementation backed by
// in-memory fixtures, suitable for driving the explore handler in tests.
//
// It serves anonymously (no auth challenge), supports manifests, blobs,
// tags/list, and the referrers fallback-tag scheme. Enough for the happy paths
// the explorer exercises.
type fakeRegistry struct {
	server *httptest.Server

	mu        sync.Mutex
	manifests map[string]map[string]manifestEntry // repo -> reference -> entry
	blobs     map[string]map[string][]byte        // repo -> digest -> bytes
	tagOrder  map[string][]string                 // repo -> insertion-ordered list of tags

	requests []recordedRequest
}

type manifestEntry struct {
	body        []byte
	contentType string
	digest      string
}

type recordedRequest struct {
	method string
	path   string
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	fr := &fakeRegistry{
		manifests: map[string]map[string]manifestEntry{},
		blobs:     map[string]map[string][]byte{},
		tagOrder:  map[string][]string{},
	}
	fr.server = httptest.NewServer(http.HandlerFunc(fr.handle))
	t.Cleanup(fr.server.Close)
	return fr
}

// Host returns the host:port suffix (without scheme) so callers can build
// references like "<host>/repo:tag". 127.0.0.1 triggers the http scheme in
// internal/ggcr/name automatically.
func (f *fakeRegistry) Host() string {
	return strings.TrimPrefix(f.server.URL, "http://")
}

// addBlob records a blob under repo by its sha256 digest and returns the digest.
func (f *fakeRegistry) addBlob(repo string, body []byte) string {
	digest := sha256Digest(body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.blobs[repo] == nil {
		f.blobs[repo] = map[string][]byte{}
	}
	f.blobs[repo][digest] = body
	return digest
}

// addManifest records a manifest body addressable by both digest and the given
// human reference (tag), returning the digest. An empty ref skips tagging.
func (f *fakeRegistry) addManifest(repo, ref string, body []byte, contentType string) string {
	digest := sha256Digest(body)
	entry := manifestEntry{body: body, contentType: contentType, digest: digest}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.manifests[repo] == nil {
		f.manifests[repo] = map[string]manifestEntry{}
	}
	f.manifests[repo][digest] = entry
	if ref != "" && ref != digest {
		if _, exists := f.manifests[repo][ref]; !exists {
			f.tagOrder[repo] = append(f.tagOrder[repo], ref)
		}
		f.manifests[repo][ref] = entry
	}
	return digest
}

// addImage installs a minimal OCI image: a config blob (synthesized from cfg),
// no layers, and the manifest pointing at the config. Returns manifest digest.
func (f *fakeRegistry) addImage(repo, tag string, cfg map[string]any) string {
	if cfg == nil {
		cfg = map[string]any{
			"architecture": "amd64",
			"os":           "linux",
			"config":       map[string]any{"Cmd": []string{"/bin/sh"}},
			"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{}},
		}
	}
	cfgBody, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	cfgDigest := f.addBlob(repo, cfgBody)
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest":    cfgDigest,
			"size":      len(cfgBody),
		},
		"layers": []any{},
	}
	mfBody, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	return f.addManifest(repo, tag, mfBody, "application/vnd.oci.image.manifest.v1+json")
}

// tarFile describes a single file entry to embed in a tar fixture.
type tarFile struct {
	name string
	mode int64
	body string
	link string // for typeflag = link/symlink, the target
	typ  byte   // tar.TypeReg, tar.TypeDir, tar.TypeSymlink, ...
}

// buildTarGz returns a deterministic gzip-compressed tar archive over files.
// Headers use ModTime=0, Uid=Gid=0, and tar.FormatPAX with no PAX records, and
// gzip is invoked with no Name/Comment/ModTime — so the output bytes (and
// therefore the digest) are stable across runs.
func buildTarGz(t *testing.T, files []tarFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.ModTime = time.Time{}
	tw := tar.NewWriter(zw)
	for _, f := range files {
		typ := f.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     f.name,
			Mode:     f.mode,
			Size:     int64(len(f.body)),
			ModTime:  time.Unix(0, 0).UTC(),
			Typeflag: typ,
			Linkname: f.link,
			Format:   tar.FormatPAX,
		}
		if hdr.Mode == 0 {
			if typ == tar.TypeDir {
				hdr.Mode = 0o755
			} else {
				hdr.Mode = 0o644
			}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader(%q): %v", f.name, err)
		}
		if typ == tar.TypeReg && len(f.body) > 0 {
			if _, err := tw.Write([]byte(f.body)); err != nil {
				t.Fatalf("tar Write(%q): %v", f.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

// buildTar returns a deterministic uncompressed tar archive over files,
// using the same header conventions as buildTarGz.
func buildTar(t *testing.T, files []tarFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		typ := f.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     f.name,
			Mode:     f.mode,
			Size:     int64(len(f.body)),
			ModTime:  time.Unix(0, 0).UTC(),
			Typeflag: typ,
			Linkname: f.link,
			Format:   tar.FormatPAX,
		}
		if hdr.Mode == 0 {
			if typ == tar.TypeDir {
				hdr.Mode = 0o755
			} else {
				hdr.Mode = 0o644
			}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader(%q): %v", f.name, err)
		}
		if typ == tar.TypeReg && len(f.body) > 0 {
			if _, err := tw.Write([]byte(f.body)); err != nil {
				t.Fatalf("tar Write(%q): %v", f.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	return buf.Bytes()
}

// buildTarZst returns a deterministic zstd-compressed tar archive.
func buildTarZst(t *testing.T, files []tarFile) []byte {
	t.Helper()
	plain := buildTar(t, files)
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	if _, err := zw.Write(plain); err != nil {
		t.Fatalf("zstd Write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zstd Close: %v", err)
	}
	return buf.Bytes()
}

func sha256Digest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (f *fakeRegistry) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, recordedRequest{method: r.Method, path: r.URL.Path})
	f.mu.Unlock()

	p := r.URL.Path
	if p == "/v2/" || p == "/v2" {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}
	if p == "/v2/_catalog" {
		f.serveCatalog(w, r)
		return
	}
	if repo, kind, id, ok := parseV2Path(p); ok {
		switch kind {
		case "manifests":
			f.serveManifest(w, r, repo, id)
			return
		case "blobs":
			f.serveBlob(w, r, repo, id)
			return
		case "tags":
			f.serveTags(w, r, repo)
			return
		case "referrers":
			f.serveReferrers(w, r, repo, id)
			return
		}
	}
	http.NotFound(w, r)
}

// parseV2Path splits "/v2/<name>/<kind>/<id>" handling repo names that contain
// slashes. kind ∈ {manifests, blobs, referrers, tags}.
func parseV2Path(p string) (repo, kind, id string, ok bool) {
	if !strings.HasPrefix(p, "/v2/") {
		return
	}
	rest := strings.TrimPrefix(p, "/v2/")
	for _, k := range []string{"manifests", "blobs", "referrers"} {
		marker := "/" + k + "/"
		if i := strings.Index(rest, marker); i >= 0 {
			return rest[:i], k, rest[i+len(marker):], true
		}
	}
	if strings.HasSuffix(rest, "/tags/list") {
		return strings.TrimSuffix(rest, "/tags/list"), "tags", "", true
	}
	return
}

func (f *fakeRegistry) serveManifest(w http.ResponseWriter, r *http.Request, repo, ref string) {
	f.mu.Lock()
	entry, ok := f.manifests[repo][ref]
	f.mu.Unlock()
	if !ok {
		writeRegistryError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest not found")
		return
	}
	w.Header().Set("Content-Type", entry.contentType)
	w.Header().Set("Docker-Content-Digest", entry.digest)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(entry.body)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(entry.body)
}

func (f *fakeRegistry) serveBlob(w http.ResponseWriter, r *http.Request, repo, digest string) {
	f.mu.Lock()
	body, ok := f.blobs[repo][digest]
	f.mu.Unlock()
	if !ok {
		writeRegistryError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func (f *fakeRegistry) serveCatalog(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	repos := make([]string, 0, len(f.manifests))
	for repo := range f.manifests {
		repos = append(repos, repo)
	}
	f.mu.Unlock()
	sort.Strings(repos)
	body, _ := json.Marshal(map[string]any{"repositories": repos})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func (f *fakeRegistry) serveTags(w http.ResponseWriter, r *http.Request, repo string) {
	f.mu.Lock()
	tags := append([]string(nil), f.tagOrder[repo]...)
	f.mu.Unlock()
	body, _ := json.Marshal(map[string]any{
		"name": repo,
		"tags": tags,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// serveReferrers returns 404 (no Docker-Distribution-Api-Version header) so the
// remote package falls through to the fallback-tag scheme. With no fallback tag
// configured this in turn 404s and the package returns an empty referrers index.
func (f *fakeRegistry) serveReferrers(w http.ResponseWriter, r *http.Request, repo, digest string) {
	writeRegistryError(w, http.StatusNotFound, "NOT_FOUND", "referrers api not supported")
}

func writeRegistryError(w http.ResponseWriter, status int, code, msg string) {
	body, _ := json.Marshal(map[string]any{
		"errors": []map[string]any{{"code": code, "message": msg}},
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
}
