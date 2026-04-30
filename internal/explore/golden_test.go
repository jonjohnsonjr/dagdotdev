package explore

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "update golden files in testdata/golden")

// TestMain pins the package's local time zone to UTC so SOCI tar listings
// format ModTimes deterministically regardless of host timezone.
func TestMain(m *testing.M) {
	os.Setenv("TZ", "UTC")
	time.Local = time.UTC
	os.Exit(m.Run())
}

// goldenCase describes a single recorded request through the explore handler
// against a fake registry populated by setup. The captured response body is
// compared to testdata/golden/<name>.html (run with -update to regenerate).
type goldenCase struct {
	name string
	// setup populates fr with fixtures and returns the URL path+query to hit
	// (e.g. "/?image=" + fr.Host() + "/repo@" + digest).
	setup func(t *testing.T, fr *fakeRegistry) string
	// warmup is an optional callback that returns URLs to hit (against the
	// same handler) before the recorded request. Useful for SOCI tests that
	// need the index cache pre-populated so the second request follows the
	// random-access indexedFS code path instead of the streaming tryNewIndex
	// path.
	warmup func(fr *fakeRegistry) []string
	// optional extra request headers
	headers map[string]string
	// expected status code; defaults to 200
	wantStatus int
}

func runGolden(t *testing.T, tc goldenCase) {
	t.Helper()
	// Routes that touch SOCI rely on indexCache. With no env var set,
	// buildIndexCache produces an empty multiCache that I/O-fails every op,
	// so SOCI indexing falls over. Pointing CACHE_DIR at a per-test temp dir
	// gives us a real on-disk cache for the duration of the test.
	t.Setenv("CACHE_DIR", t.TempDir())

	fr := newFakeRegistry(t)
	target := tc.setup(t, fr)

	h := New(WithUserAgent("test-explore"))

	// Warm up cache via prior requests against the same handler instance.
	if tc.warmup != nil {
		for _, u := range tc.warmup(fr) {
			warmReq := httptest.NewRequest(http.MethodGet, u, nil)
			warmReq.Header.Set("User-Agent", "explore-test/1.0")
			warmReq.Header.Set("Accept-Encoding", "identity")
			h.ServeHTTP(httptest.NewRecorder(), warmReq)
		}
	}

	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("User-Agent", "explore-test/1.0")
	// Suppress gzhttp wrapping so the captured body is plain HTML.
	req.Header.Set("Accept-Encoding", "identity")
	for k, v := range tc.headers {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	want := tc.wantStatus
	if want == 0 {
		want = http.StatusOK
	}
	if rec.Code != want {
		t.Errorf("status: got %d, want %d\nbody: %s", rec.Code, want, rec.Body.String())
	}

	got := normalizeGolden(rec.Body.String(), fr.Host())
	goldenPath := filepath.Join("testdata", "golden", tc.name+".html")

	if *update {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}

	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create): %v", goldenPath, err)
	}
	if got != string(wantBytes) {
		t.Errorf("golden %s mismatch.\n--- want ---\n%s\n--- got ---\n%s", goldenPath, string(wantBytes), got)
	}
}

// normalizeGolden replaces test-run-specific fragments (random ports,
// timing strings) with stable placeholders so the captured body is
// byte-stable across runs.
func normalizeGolden(body, host string) string {
	if host != "" {
		body = strings.ReplaceAll(body, host, "REGISTRY")
	}
	// In case the host appears URL-escaped (rare, but %3A for ':' in some links).
	body = strings.ReplaceAll(body, escapeColon(host), escapeColon("REGISTRY"))
	// Belt-and-suspenders: any leftover 127.0.0.1:NNNN patterns.
	body = loopbackPort.ReplaceAllString(body, "REGISTRY")
	// SOCI rendering injects an "Indexed in 12.345µs" line whose duration
	// varies; normalize to a fixed token.
	body = indexedIn.ReplaceAllString(body, "Indexed in DURATION")
	return body
}

var (
	loopbackPort = regexp.MustCompile(`127\.0\.0\.1:\d+`)
	indexedIn    = regexp.MustCompile(`Indexed in [0-9.]+(?:µ|m|n)?s`)
)

func escapeColon(s string) string {
	return strings.ReplaceAll(s, ":", "%3A")
}
