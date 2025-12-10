package apk

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/maps"

	"github.com/digitorus/timestamp"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/authn"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/logs"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/v1"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jonjohnsonjr/dagdotdev/internal/forks/elf"
	httpserve "github.com/jonjohnsonjr/dagdotdev/internal/forks/http"
	"github.com/jonjohnsonjr/dagdotdev/internal/soci"
	"github.com/jonjohnsonjr/dagdotdev/internal/xxd"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/klauspost/compress/gzhttp"
)

// We should not buffer blobs greater than 2MB
const tooBig = 1 << 24
const respTooBig = 1 << 25

const printToken = ` -u "user:$(chainctl auth token --audience apk.cgr.dev)"`

var defaultExamples = []string{
	"packages.wolfi.dev/os/aarch64",
	"packages.wolfi.dev/os/x86_64",
	"packages.cgr.dev/extras/aarch64",
	"packages.cgr.dev/extras/x86_64",
	"apk.cgr.dev/chainguard/aarch64",
	"apk.cgr.dev/chainguard/x86_64",
	"dl-cdn.alpinelinux.org/alpine/edge/main/aarch64",
	"dl-cdn.alpinelinux.org/alpine/edge/main/armhf",
	"dl-cdn.alpinelinux.org/alpine/edge/main/armv7",
	"dl-cdn.alpinelinux.org/alpine/edge/main/mips64",
	"dl-cdn.alpinelinux.org/alpine/edge/main/ppc64le",
	"dl-cdn.alpinelinux.org/alpine/edge/main/riscv64",
	"dl-cdn.alpinelinux.org/alpine/edge/main/s390x",
	"dl-cdn.alpinelinux.org/alpine/edge/main/x86",
	"dl-cdn.alpinelinux.org/alpine/edge/main/x86_64",
	"dl-cdn.alpinelinux.org/alpine/edge/community/aarch64",
	"dl-cdn.alpinelinux.org/alpine/edge/community/x86_64",
}

type handler struct {
	mux       http.Handler
	keychain  authn.Keychain
	cgauth    Authenticator
	userAgent string

	args []string

	examples []string

	tocCache   cache
	indexCache cache
	apkCache   *apkCache

	sync.Mutex
	inflight map[string]*soci.Indexer
}

type Option func(h *handler)

func WithKeychain(keychain authn.Keychain) Option {
	return func(h *handler) {
		h.keychain = keychain
	}
}

func WithAuth(a Authenticator) Option {
	return func(h *handler) {
		h.cgauth = a
	}
}

func WithUserAgent(ua string) Option {
	return func(h *handler) {
		h.userAgent = ua
	}
}

func WithExamples(examples []string) Option {
	return func(h *handler) {
		// Presumably if we're pasing examples in, they're more interesting than the defaults,
		// so we will put them first.
		h.examples = slices.Concat(examples, h.examples)
	}
}

func New(args []string, opts ...Option) http.Handler {
	h := handler{
		args:       args,
		inflight:   map[string]*soci.Indexer{},
		tocCache:   buildTocCache(),
		indexCache: buildIndexCache(),
		apkCache:   buildApkCache(),
		examples:   defaultExamples,
	}

	for _, opt := range opts {
		opt(&h)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", h.errHandler(h.renderResponse))

	mux.HandleFunc("/fs/", h.errHandler(h.renderFS))
	mux.HandleFunc("/size/", h.errHandler(h.renderFat))

	// Janky workaround for downloading via the "urls" field.
	mux.HandleFunc("/http/", h.errHandler(h.renderFS))
	mux.HandleFunc("/https/", h.errHandler(h.renderFS))
	mux.HandleFunc("/file/", h.errHandler(h.renderLocalFS))

	// Try to detect mediaType.
	mux.HandleFunc("/blob/", h.errHandler(h.renderFS))

	h.mux = gzhttp.GzipHandler(mux)

	return &h
}

func splitFsURL(p string) (string, string, error) {
	for _, prefix := range []string{"/fs/", "/layers/", "/https/", "/http/", "/blob/", "/cache/", "/size/", "/file/"} {
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(p, prefix), prefix, nil
		}
	}

	return "", "", fmt.Errorf("unexpected path: %v", p)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: Avoid double logging on cloud run.
	log.Printf("%v", r.URL)

	start := time.Now()
	defer func() {
		log.Printf("%v (%s)", r.URL, time.Since(start))
	}()

	if r.URL.Path == "/favicon.svg" || r.URL.Path == "/favicon.ico" {
		w.Header().Set("Cache-Control", "max-age=3600")
		http.ServeFile(w, r, filepath.Join(os.Getenv("KO_DATA_PATH"), "favicon.svg"))
		return
	}
	if r.URL.Path == "/robots.txt" {
		w.Header().Set("Cache-Control", "max-age=3600")
		http.ServeFile(w, r, filepath.Join(os.Getenv("KO_DATA_PATH"), "robots.txt"))
		return
	}

	h.mux.ServeHTTP(w, r)
}

type HandleFuncE func(http.ResponseWriter, *http.Request) error

func (h *handler) errHandler(hfe HandleFuncE) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := hfe(w, r); err != nil {
			log.Printf("%s: %v", r.URL.Path, err)
			fmt.Fprintf(w, "failed: %s", html.EscapeString(err.Error()))
		}
	}
}

func (h *handler) renderResponse(w http.ResponseWriter, r *http.Request) error {
	qs := r.URL.Query()

	if q := qs.Get("url"); q != "" {
		u, err := url.PathUnescape(q)
		if err != nil {
			return err
		}

		p := u
		if before, after, ok := strings.Cut(p, "://"); ok {
			p = path.Join(before, after)
		}

		http.Redirect(w, r, p, http.StatusFound)
		return nil
	}

	data := Landing{
		Examples: h.examples,
	}
	if args := h.args; len(args) != 0 {
		indices := []string{}
		apks := []string{}
		for _, arg := range args {
			if err := filepath.WalkDir(arg, func(path string, d fs.DirEntry, err error) error {
				if strings.HasSuffix(path, "APKINDEX.tar.gz") {
					indices = append(indices, path)
				} else if strings.HasSuffix(path, ".apk") {
					apks = append(apks, path)
				}
				return nil
			}); err != nil {
				return err
			}
		}

		data.Indices = indices
		data.Apks = apks
	}

	return landingTmpl.Execute(w, data)
}

func renderOctets(w http.ResponseWriter, b []byte) error {
	fmt.Fprint(w, "<pre>")
	if _, err := io.Copy(xxd.NewWriter(w, int64(len(b))), bytes.NewReader(b)); err != nil {
		return err
	}
	fmt.Fprint(w, "</pre>")

	return nil
}

func (h *handler) renderContent(w http.ResponseWriter, r *http.Request, b []byte, output *jsonOutputter, u url.URL) error {
	switch r.URL.Query().Get("render") {
	case "raw":
		fmt.Fprint(w, "<pre>")
		if _, err := w.Write(b); err != nil {
			return err
		}
		fmt.Fprint(w, "</pre>")
	case "x509":
		return renderx509(w, b)
	case "cert":
		return renderCert(w, b, u)
	case "der":
		return renderDer(w, b)
	case "xxd":
		return renderOctets(w, b)
	case "timestamp":
		ts, err := timestamp.Parse(b)
		if err != nil {
			return err
		}
		j, err := json.Marshal(ts)
		if err != nil {
			return err
		}
		return renderJSON(output, j)
	default:
		return renderJSON(output, b)
	}

	return nil

}

func (h *handler) renderFile(w http.ResponseWriter, r *http.Request, ref string, kind string, blob *sizeSeeker) error {
	// Allow this to be cached for an hour.
	w.Header().Set("Cache-Control", "max-age=3600, immutable")

	httpserve.ServeContent(w, r, "", time.Time{}, blob, func(w http.ResponseWriter, r *http.Request, ctype string) error {
		// Kind at this poin can be "gzip", "zstd" or ""
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
			return err
		}
		desc := v1.Descriptor{
			Size: blob.Size(),
		}
		if size := r.URL.Query().Get("size"); size != "" {
			if parsed, err := strconv.ParseInt(size, 10, 64); err == nil {
				desc.Size = parsed
			}
		}
		header := headerData(ref)

		before, _, ok := strings.Cut(ref, "@")
		if ok {
			u, err := refToUrl(before)
			if err != nil {
				return err
			}
			scheme, _, ok := strings.Cut(u, "://")
			if !ok {
				return fmt.Errorf("no scheme in %q", u)
			}
			if scheme == "file" {
				u = strings.TrimPrefix(u, "file://")
			}

			if scheme == "file" {
				header.JQ = "cat" + " " + u
			} else if strings.Contains(ref, "apk.cgr.dev/chainguard-private") {
				header.JQ = "curl -sL" + printToken + " " + u
			} else {
				header.JQ = "curl -sL" + " " + u
			}
			if kind == "zstd" {
				header.JQ += " | zstd -d"
			} else if kind == "gzip" {
				header.JQ += " | gunzip"
			}
			if r.URL.Query().Get("render") == "elf" {
				header.JQ += " | objdump -x -"
			} else {
				tooBig := int64(httpserve.TooBig)
				if ctype == "elf" {
					tooBig = elf.TooBig
				}
				if blob.size < 0 || blob.size > tooBig {
					header.JQ += fmt.Sprintf(" | head -c %d", tooBig)
				}
				if !strings.HasPrefix(ctype, "text/") && !strings.Contains(ctype, "json") {
					header.JQ += " | xxd"
				}
			}
		}

		return bodyTmpl.Execute(w, header)
	})

	return nil
}

// foo/bar/baz/APKINDEX.tar.gz => HEAD for etag, redirect.
// foo/bar/baz/APKINDEX.tar.gz@etag:12345 => Fetch from cache by etag (backfill if missing), render as tarball fs.
// foo/bar/baz/APKINDEX.tar.gz@etag:12345/{DESCRIPTION/APKINDEX} => As above, but render files.
// foo/bar/baz/foo.apk => Fetch control hash from APKINDEX.tar.gz?
// foo/bar/baz/foo.apk@sha1:abcd => Control section => TODO: Show signature _and_ control?
// foo/bar/baz/foo.apk@sha256:def321 => Data section.
func (h *handler) renderFS(w http.ResponseWriter, r *http.Request) error {
	qs := r.URL.Query()
	qss := "?"
	provides, ok := qs["provide"]
	if ok {
		for i, dep := range provides {
			provides[i] = url.QueryEscape(dep)
		}
		qss += "provide=" + strings.Join(provides, "&provide=")
	}
	depends, ok := qs["depend"]
	if ok {
		for i, dep := range depends {
			depends[i] = url.QueryEscape(dep)
		}
		qss += "&depend=" + strings.Join(depends, "&depend=")
	}
	full := qs.Get("full")
	if full != "" {
		qss += "&full=" + full
	}
	search := qs.Get("search")
	if search != "" {
		qss += "&search=" + search
	}
	short := qs.Get("short")
	if short != "" {
		qss += "&short=" + short
	}
	sort := qs.Get("sort")
	if short != "" {
		qss += "&sort=" + sort
	}
	p, root, err := splitFsURL(r.URL.Path)
	if err != nil {
		return err
	}

	// TODO: We only _really_ want to do this for APKINDEX.tar.gz
	// For the actual foo.apk fetch WITHOUT a hash (unlikely), we need to look up control section
	// hash in the index and redirect to that.
	u, err := getUpstreamURL(r)
	if err != nil {
		return err
	}

	ref := ""

	// We want to get the part after @ but before the filepath.
	before, rest, ok := strings.Cut(p, "@")
	if !ok || strings.Contains(u, "APKINDEX.tar.gz") {
		etag, err := h.headUrl(u)
		if err != nil {
			return fmt.Errorf("resolving etag: %w", err)
		}

		if etag == "" {
			return h.fallback(w, r, u)
		}

		if unquoted, err := strconv.Unquote(strings.TrimPrefix(etag, "W/")); err == nil {
			etag = unquoted
		}

		// TODO: Consider caring about W/"..." vs "..."?
		etagHex := hex.EncodeToString([]byte(etag))

		if _, err := hex.DecodeString(etag); err == nil {
			etagHex = etag
		}

		// We want to get the part after @ but before the filepath.
		before, rest, ok := strings.Cut(p, "@")
		if !ok {
			redir := fmt.Sprintf("%s@etag:%s", r.URL.Path, etagHex)
			if before, rest, ok := strings.Cut(r.URL.Path, "APKINDEX.tar.gz"); ok {
				redir = fmt.Sprintf("%sAPKINDEX.tar.gz@etag:%s%s", before, etagHex, rest)
			} else if p := r.URL.Query().Get("path"); p != "" {
				redir = fmt.Sprintf("%s@etag:%s/%s", before, etagHex, p)
			}
			http.Redirect(w, r, redir+qss, http.StatusFound)
			return nil
		}

		redir := fmt.Sprintf("%s%s@etag:%s", root, before, etagHex)
		ref = before + "@" + rest

		if digest, final, ok := strings.Cut(rest, "/"); ok {
			ref = before + "@" + digest
			redir = redir + "/" + final
		}

		if redir != r.URL.Path {
			if strings.Contains(before, "APKINDEX.tar.gz") {
				http.Redirect(w, r, redir+qss, http.StatusFound)
				return nil
			}
		}

		ref = root + ref
	} else {
		ref = before + "@" + rest

		if digest, _, ok := strings.Cut(rest, "/"); ok {
			ref = before + "@" + digest
		}

		ref = root + ref
	}

	index, err := h.getIndex(r.Context(), ref)
	if err != nil {
		return fmt.Errorf("indexCache.Index(%q) = %w", ref, err)
	}
	if index != nil {
		fs, err := h.indexedFS(r, ref, index)
		if err != nil {
			return err
		}

		if strings.HasSuffix(r.URL.Path, "APKINDEX") {
			filename := strings.TrimPrefix(r.URL.Path, "/")
			open := func() (io.ReadCloser, error) {
				return fs.Open(filename)
			}

			return h.renderIndex(w, r, open, ref)
		} else if strings.HasSuffix(r.URL.Path, ".spdx.json") {
			filename := strings.TrimPrefix(r.URL.Path, "/")
			rc, err := fs.Open(filename)
			if err != nil {
				return fmt.Errorf("open(%q): %w", filename, err)
			}
			defer rc.Close()

			return h.renderSBOM(w, r, rc, ref)
		} else if strings.HasSuffix(r.URL.Path, "/.PKGINFO") {
			filename := strings.TrimPrefix(r.URL.Path, "/")
			rc, err := fs.Open(filename)
			if err != nil {
				return fmt.Errorf("open(%q): %w", filename, err)
			}
			defer rc.Close()

			return h.renderPkgInfo(w, r, rc, ref)
		}

		httpserve.FileServer(httpserve.FS(fs)).ServeHTTP(w, r)
		return nil
	}

	// Determine if this is actually a filesystem thing.
	blob, prefix, err := h.fetchBlob(w, r)
	if err != nil {
		if strings.Contains(r.URL.Path, ".apk@") {
			return h.renderApkError(w, r, ref, err)
		}
		return fmt.Errorf("fetchBlob: %w", err)
	}

	kind, original, unwrapped, err := h.tryNewIndex(w, r, prefix, ref, blob)
	if err != nil {
		return fmt.Errorf("failed to index blob %q: %w", ref, err)
	}
	if unwrapped != nil {
		logs.Debug.Printf("unwrapped, kind = %q", kind)
		seek := &sizeSeeker{unwrapped, -1}
		return h.renderFile(w, r, ref, kind, seek)
	}
	if original != nil {
		logs.Debug.Printf("original")
		seek := &sizeSeeker{original, blob.size}
		return h.renderFile(w, r, ref, kind, seek)
	}

	logs.Debug.Printf("ref=%q, prefix=%q, kind=%q, origin=%v, unwrapped=%v, err=%v", ref, prefix, kind, original, unwrapped, err)

	return nil
}

func (h *handler) renderLocalFS(w http.ResponseWriter, r *http.Request) error {
	qs := r.URL.Query()
	qss := "?"
	provides, ok := qs["provide"]
	if ok {
		for i, dep := range provides {
			provides[i] = url.QueryEscape(dep)
		}
		qss += "provide=" + strings.Join(provides, "&provide=")
	}
	depends, ok := qs["depend"]
	if ok {
		for i, dep := range depends {
			depends[i] = url.QueryEscape(dep)
		}
		qss += "&depend=" + strings.Join(depends, "&depend=")
	}
	full := qs.Get("full")
	if full != "" {
		qss += "&full=" + full
	}
	search := qs.Get("search")
	if search != "" {
		qss += "&search=" + search
	}
	p, root, err := splitFsURL(r.URL.Path)
	if err != nil {
		return err
	}

	// TODO: We only _really_ want to do this for APKINDEX.tar.gz
	// For the actual foo.apk fetch WITHOUT a hash (unlikely), we need to look up control section
	// hash in the index and redirect to that.
	u, err := getUpstreamURL(r)
	if err != nil {
		return err
	}

	u = strings.TrimPrefix(u, "file://")

	ref := ""
	// We want to get the part after @ but before the filepath.
	before, rest, ok := strings.Cut(p, "@")
	if !ok || strings.Contains(u, "APKINDEX.tar.gz") {
		// TODO: This is dumb we should not even bother indexing local things.
		f, err := os.Open(u)
		if err != nil {
			return err
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		etagHex := hex.EncodeToString(h.Sum(make([]byte, 0, h.Size())))

		// We want to get the part after @ but before the filepath.
		before, rest, ok := strings.Cut(p, "@")
		if !ok {
			redir := fmt.Sprintf("%s@etag:%s", r.URL.Path, etagHex)
			if before, rest, ok := strings.Cut(r.URL.Path, "APKINDEX.tar.gz"); ok {
				redir = fmt.Sprintf("%sAPKINDEX.tar.gz@etag:%s%s", before, etagHex, rest)
			} else if p := r.URL.Query().Get("path"); p != "" {
				redir = fmt.Sprintf("%s@etag:%s/%s", before, etagHex, p)
			}
			http.Redirect(w, r, redir+qss, http.StatusFound)
			return nil
		}

		redir := fmt.Sprintf("%s%s@etag:%s", root, before, etagHex)
		ref = before + "@" + rest

		if digest, final, ok := strings.Cut(rest, "/"); ok {
			ref = before + "@" + digest
			redir = redir + "/" + final
		}

		if redir != r.URL.Path {
			if strings.Contains(before, "APKINDEX.tar.gz") {
				http.Redirect(w, r, redir+qss, http.StatusFound)
				return nil
			}
		}

		ref = root + ref
	} else {
		ref = before + "@" + rest

		if digest, _, ok := strings.Cut(rest, "/"); ok {
			ref = before + "@" + digest
		}

		ref = root + ref
	}

	index, err := h.getIndex(r.Context(), ref)
	if err != nil {
		return fmt.Errorf("indexCache.Index(%q) = %w", ref, err)
	}
	if index != nil {
		fs, err := h.indexedFS(r, ref, index)
		if err != nil {
			return err
		}

		if strings.HasSuffix(r.URL.Path, "APKINDEX") {
			filename := strings.TrimPrefix(r.URL.Path, "/")
			open := func() (io.ReadCloser, error) {
				return fs.Open(filename)
			}

			return h.renderIndex(w, r, open, ref)
		} else if strings.HasSuffix(r.URL.Path, ".spdx.json") {
			filename := strings.TrimPrefix(r.URL.Path, "/")
			rc, err := fs.Open(filename)
			if err != nil {
				return fmt.Errorf("open(%q): %w", filename, err)
			}
			defer rc.Close()

			return h.renderSBOM(w, r, rc, ref)
		} else if strings.HasSuffix(r.URL.Path, "/.PKGINFO") {
			filename := strings.TrimPrefix(r.URL.Path, "/")
			rc, err := fs.Open(filename)
			if err != nil {
				return fmt.Errorf("open(%q): %w", filename, err)
			}
			defer rc.Close()

			return h.renderPkgInfo(w, r, rc, ref)
		}

		httpserve.FileServer(httpserve.FS(fs)).ServeHTTP(w, r)
		return nil
	}

	// Determine if this is actually a filesystem thing.
	blob, prefix, err := h.fetchArg(w, r, u)
	if err != nil {
		return fmt.Errorf("fetchBlob: %w", err)
	}

	kind, original, unwrapped, err := h.tryNewIndex(w, r, prefix, ref, blob)
	if err != nil {
		return fmt.Errorf("failed to index blob %q: %w", ref, err)
	}
	if unwrapped != nil {
		logs.Debug.Printf("unwrapped, kind = %q", kind)
		seek := &sizeSeeker{unwrapped, -1}
		return h.renderFile(w, r, ref, kind, seek)
	}
	if original != nil {
		logs.Debug.Printf("original")
		seek := &sizeSeeker{original, blob.size}
		return h.renderFile(w, r, ref, kind, seek)
	}

	logs.Debug.Printf("ref=%q, prefix=%q, kind=%q, origin=%v, unwrapped=%v, err=%v", ref, prefix, kind, original, unwrapped, err)

	return nil
}

func getUpstreamURL(r *http.Request) (string, error) {
	return refToUrl(r.URL.Path)
}

type fileSeeker struct {
	file string
}

func (fs *fileSeeker) Reader(ctx context.Context, off int64, end int64) (io.ReadCloser, error) {
	logs.Debug.Printf("cacheSeeker.Reader(%d, %d)", off, end)
	f, err := os.Open(fs.file)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(io.NewSectionReader(f, off, end-off)), nil
}

func (h *handler) indexedFS(r *http.Request, ref string, index soci.Index) (*soci.SociFS, error) {
	toc := index.TOC()
	if toc == nil {
		return nil, fmt.Errorf("this should not happen")
	}
	mt := toc.MediaType

	var blob soci.BlobSeeker

	cachedUrl, err := getUpstreamURL(r)
	if err != nil {
		return nil, err
	}

	if _, p, ok := strings.Cut(cachedUrl, "file://"); ok {
		blob = &fileSeeker{p}
	} else {
		blob = LazyBlob(cachedUrl, toc.Csize, h.addAuth)
	}
	prefix := strings.TrimPrefix(ref, "/")
	fs := soci.FS(index, blob, prefix, ref, respTooBig, types.MediaType(mt), h.renderHeader)

	return fs, nil
}

func (h *handler) jq(b []byte, r *http.Request, header *HeaderData) ([]byte, error) {
	jq, ok := r.URL.Query()["jq"]
	if !ok {
		header.JQ += " | jq ."
		return b, nil
	}

	var (
		err error
		exp string
	)

	exps := []string{header.JQ}

	for _, j := range jq {
		if debug {
			log.Printf("j = %s", j)
		}
		b, exp, err = evalBytes(j, b)
		if err != nil {
			return nil, err
		}
		exps = append(exps, exp)
	}

	header.JQ = strings.Join(exps, " | ")
	return b, nil
}

func headerData(_ string) *HeaderData {
	return &HeaderData{}
}

func refToUrl(p string) (string, error) {
	scheme := "https://"
	if strings.HasPrefix(p, "/file/") {
		p = strings.TrimPrefix(p, "/file/")
		scheme = "file://"
	} else if strings.HasPrefix(p, "/http/") {
		p = strings.TrimPrefix(p, "/http/")
		scheme = "http://"
	} else {
		p = strings.TrimPrefix(p, "/https/")
		p = strings.TrimPrefix(p, "/size/")
	}
	before, _, ok := strings.Cut(p, "@")
	if !ok {
		if b, _, ok := strings.Cut(p, "APKINDEX.tar.gz"); ok {
			before = path.Join(b, "APKINDEX.tar.gz")
		}
	}
	u, err := url.PathUnescape(before)
	if err != nil {
		return "", err
	}
	u = scheme + u

	return strings.TrimSuffix(u, "/"), nil
}

func (h *handler) renderHeader(w http.ResponseWriter, r *http.Request, fname string, prefix string, ref string, kind string, mediaType types.MediaType, size int64, f httpserve.File, ctype string) error {
	header := headerData(ref)

	search := r.URL.Query().Get("search")
	pax := r.URL.Query().Get("pax") == "true"

	stat, err := f.Stat()
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
		return err
	}

	filename := strings.TrimPrefix(fname, "/"+prefix)
	filename = strings.TrimPrefix(filename, "/")

	tarh, ok := stat.Sys().(*tar.Header)
	if ok {
		filename = tarh.Name
		if pax {
			header.PAXRecords = maps.Clone(tarh.PAXRecords)
			for k, v := range header.PAXRecords {
				header.PAXRecords[k] = strconv.QuoteToASCII(v)
			}
		}
	} else {
		if !stat.IsDir() {
			logs.Debug.Printf("not a tar header or directory")
		}
	}

	tarflags := "tar -Ox"
	if kind == "tar+gzip" {
		tarflags = "tar -Oxz"
	} else if kind == "tar+zstd" {
		tarflags = "tar --zstd -Ox"
	}

	filelink := filename

	// Compute links for JQ
	fprefix := ""
	if strings.HasPrefix(filename, "./") {
		fprefix = "./"
	}
	filename = strings.TrimSuffix(filename, "/")
	dir := path.Dir(filename)
	if dir != "." {
		base := path.Base(filename)
		sep := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(filename, fprefix), dir), base)

		href := path.Join(prefix, dir)
		htext := fprefix + dir + sep

		logs.Debug.Printf("dir=%q, sep=%q, base=%q, href=%q, htext=%q", dir, sep, base, href, htext)
		dirlink := fmt.Sprintf(`<a class="mt" href="/%s">%s</a>`, href, htext)
		filelink = dirlink + base
	}
	if strings.Contains(ref, ".apk@") {
		if _, after, ok := strings.Cut(prefix, "/"); ok {
			href := path.Join("/size", after)
			header.SizeLink = href
		}
	}

	if stat.IsDir() {
		tarflags = "tar -tv"
		if kind == "tar+gzip" {
			tarflags = "tar -tvz"
		} else if kind == "tar+zstd" {
			tarflags = "tar --zstd -tv"
		}

		if !strings.Contains(r.URL.Path, "APKINDEX.tar.gz") {
			header.Search = ".PKGINFO"
			if search != "" {
				header.Search = search
				tarflags += fmt.Sprintf(" | grep %q", search)
			}
		}
	}

	u, err := refToUrl(ref)
	if err != nil {
		return err
	}

	scheme, after, ok := strings.Cut(u, "://")
	if !ok {
		return fmt.Errorf("no scheme in %q", u)
	}
	dir = scheme + "://" + path.Dir(after)
	if scheme == "file" {
		dir = strings.TrimPrefix(dir, "file://")
	}
	base := path.Base(u)

	before, _, ok := strings.Cut(ref, "@")
	if !ok {
		return fmt.Errorf("no @ in apk")
	}

	index := path.Join(path.Dir(before), "APKINDEX.tar.gz")

	href := fmt.Sprintf("<a class=%q href=%q>%s</a>/<a class=%q href=%q>%s</a>", "mt", index, dir, "mt", ref, base)

	u = href

	tarhref := "?pax=true"
	if !stat.IsDir() {
		if pax {
			tarhref = "?pax=false"
		}
	} else {
		tarhref = "?all=true"
		if r.URL.Query().Get("all") == "true" || search != "" {
			if pax {
				search = "" // so we cycle back to the original view
				tarhref = "?all=false&pax=false"
			} else {
				tarhref = "?all=true&pax=true"
			}
		}

		if search != "" {
			tarhref += "&search=" + search
		}
	}
	tarlink := fmt.Sprintf("<a class=%q href=%q>%s</a>", "mt", tarhref, tarflags)

	if scheme == "file" {
		header.JQ = "cat" + " " + u + " | " + tarlink + " " + filelink
	} else if strings.Contains(ref, "apk.cgr.dev/chainguard-private") {
		header.JQ = "curl -sL" + printToken + " " + u + " | " + tarlink + " " + filelink
	} else {
		header.JQ = "curl -sL" + " " + u + " | " + tarlink + " " + filelink
	}

	if !stat.IsDir() {
		if r.URL.Query().Get("render") == "elf" {
			header.JQ += " | objdump -x -"
		} else {
			tooBig := int64(httpserve.TooBig)
			if ctype == "elf" {
				tooBig = elf.TooBig
			}
			if stat.Size() > tooBig {
				header.JQ += fmt.Sprintf(" | head -c %d", tooBig)
			}
			if !strings.HasPrefix(ctype, "text/") && !strings.Contains(ctype, "json") {
				header.JQ += " | xxd"
			}
		}
	}
	// header.SizeLink = fmt.Sprintf("/size/%s?mt=%s&size=%d", ref.Context().Digest(hash.String()).String(), mediaType, int64(size))

	if err := bodyTmpl.Execute(w, header); err != nil {
		return err
	}

	if _, ok := f.(httpserve.Files); ok {
		fmt.Fprintf(w, `<div><template shadowrootmode="open"><style>
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

@keyframes twist-up {
  to {
    transform: rotateX(360deg);
  }
}</style><p><slot name="message"><span style="line-height: .707em; width: .707em; display: inline-block; animation: spin 1.0s infinite linear;">🤐</span> Loading<span><slot name="progress"></slot></span></slot></p><pre><slot name="file"></slot></pre></template>`)
	}

	return nil
}

func loadingBarSize(ref string) int {
	u, err := refToUrl(ref)
	if err != nil {
		return 0
	}
	scheme, _, ok := strings.Cut(u, "://")
	if !ok {
		return 0
	}

	loading := "Loading"
	tarflags := "tar -tvz"

	if scheme == "file" {
		return len("cat"+" "+u+" | "+tarflags) - len(loading)
	} else if strings.Contains(ref, "apk.cgr.dev/chainguard-private") {
		return len("curl -sL"+printToken+" "+u+" | "+tarflags) - len(loading)
	} else {
		return len("curl -sL"+" "+u+" | "+tarflags) - len(loading)
	}
}

type dumbEscaper struct {
	buf *bufio.Writer
}

var (
	amp = []byte("&amp;")
	lt  = []byte("&lt;")
	gt  = []byte("&gt;")
	dq  = []byte("&#34;")
	sq  = []byte("&#39;")
)

func (d *dumbEscaper) Write(p []byte) (n int, err error) {
	for i, b := range p {
		switch b {
		case '&':
			_, err = d.buf.Write(amp)
		case '<':
			_, err = d.buf.Write(lt)
		case '>':
			_, err = d.buf.Write(gt)
		case '"':
			_, err = d.buf.Write(dq)
		case '\'':
			_, err = d.buf.Write(sq)
		default:
			err = d.buf.WriteByte(b)
		}
		if err != nil {
			return i, err
		}
	}
	return len(p), d.buf.Flush()
}

func title(ref string) string {
	if before, _, ok := strings.Cut(ref, "@"); !ok {
		return path.Base(before)
	}
	return path.Base(strings.TrimSuffix(ref, "/"))
}

func (h *handler) renderSBOM(w http.ResponseWriter, r *http.Request, in fs.File, ref string) error {
	if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
		return err
	}

	stat, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}

	output := &jsonOutputter{
		w:     w,
		u:     r.URL,
		fresh: []bool{},
		mt:    r.URL.Query().Get("mt"),
	}

	header := headerData(ref)

	filename := strings.TrimPrefix(r.URL.Path, ref)
	filename = strings.TrimPrefix(filename, "/")
	filelink := filename

	dir := path.Dir(filename)
	if dir != "." {
		href := path.Join(ref, dir)
		htext := dir + "/"
		dirlink := fmt.Sprintf(`<a class="mt" href="%s">%s</a>`, href, htext)
		filelink = dirlink + path.Base(filename)
	}

	before, _, ok := strings.Cut(ref, "@")
	if ok {
		u, err := refToUrl(ref)
		if err != nil {
			return err
		}
		scheme, after, ok := strings.Cut(u, "://")
		if !ok {
			return fmt.Errorf("no scheme in %q", u)
		}
		dir := scheme + "://" + path.Dir(after)
		if scheme == "file" {
			dir = strings.TrimPrefix(dir, "file://")
		}

		base := path.Base(u)

		index := path.Join(path.Dir(before), "APKINDEX.tar.gz")

		href := fmt.Sprintf("<a class=%q href=%q>%s</a>/<a class=%q href=%q>%s</a>", "mt", index, dir, "mt", ref, base)

		u = href
		if scheme == "file" {
			header.JQ = "cat" + " " + u + " | tar -Oxz " + filelink
		} else if strings.Contains(ref, "apk.cgr.dev/chainguard-private") {
			header.JQ = "curl -sL" + printToken + " " + u + " | tar -Oxz " + filelink
		} else {
			header.JQ = "curl -sL " + " " + u + " | tar -Oxz " + filelink
		}
	}

	if stat.Size() > tooBig {
		header.JQ += fmt.Sprintf(" | head -c %d", httpserve.TooBig)
		if err := bodyTmpl.Execute(w, header); err != nil {
			return fmt.Errorf("bodyTmpl: %w", err)
		}
		dumb := &dumbEscaper{buf: bufio.NewWriter(w)}
		if _, err := io.CopyN(dumb, in, httpserve.TooBig); err != nil {
			return err
		}
		fmt.Fprint(w, footer)

		return nil
	}

	// TODO: Can we do this in a streaming way?
	input, err := io.ReadAll(io.LimitReader(in, tooBig))
	if err != nil {
		return err
	}

	// Mutates header for bodyTmpl.
	b, err := h.jq(input, r, header)
	if err != nil {
		return fmt.Errorf("h.jq: %w", err)
	}

	if err := bodyTmpl.Execute(w, header); err != nil {
		return fmt.Errorf("bodyTmpl: %w", err)
	}

	if err := h.renderContent(w, r, b, output, *r.URL); err != nil {
		if r.URL.Query().Get("render") == "xxd" {
			return fmt.Errorf("renderContent: %w", err)
		}

		fmt.Fprintf(w, "NOTE: failed to render: %v\n", err)
		if err := renderOctets(w, b); err != nil {
			return fmt.Errorf("renderContent fallback: %w", err)
		}
	}

	fmt.Fprint(w, footer)

	return nil
}

func (h *handler) fallback(w http.ResponseWriter, r *http.Request, u string) error {
	blob, err := h.fetchUrl(u)
	if err != nil {
		return fmt.Errorf("fetchUrl: %w", err)
	}

	p := u
	if before, after, ok := strings.Cut(p, "://"); ok {
		p = path.Join("/", before, after)
	}

	ref := p

	zr, err := gzip.NewReader(blob)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	tr := tar.NewReader(zr)
	fs := h.newLayerFS(tr, -1, ref, ref, "tar+gzip", types.MediaType("application/tar+gzip"))

	if strings.HasSuffix(r.URL.Path, "APKINDEX") {
		filename := strings.TrimPrefix(r.URL.Path, "/")
		open := func() (io.ReadCloser, error) {
			return fs.Open(filename)
		}

		if err := h.renderIndex(w, r, open, ref); err != nil {
			return fmt.Errorf("renderIndex(%q): %w", filename, err)
		}
	} else {
		httpserve.FileServer(fs).ServeHTTP(w, r)
	}

	return nil
}

func (h *handler) renderFat(w http.ResponseWriter, r *http.Request) error {
	mt := "application/tar+gzip"
	p, root, err := splitFsURL(r.URL.Path)
	if err != nil {
		return err
	}

	before, rest, ok := strings.Cut(p, "@")
	if !ok {
		return fmt.Errorf("no @ in %q", p)
	}

	ref := before + "@" + rest
	if digest, _, ok := strings.Cut(rest, "/"); ok {
		ref = before + "@" + digest
	}

	ref = root + ref

	index, err := h.getIndex(r.Context(), ref)
	if err != nil {
		return fmt.Errorf("indexCache.Index(%q) = %w", ref, err)
	}

	if index == nil {
		// Determine if this is actually a filesystem thing.
		blob, _, err := h.fetchBlob(w, r)
		if err != nil {
			return fmt.Errorf("fetchBlob: %w", err)
		}

		index, err = h.createIndex(r.Context(), blob, blob.size, ref, 0, mt)
		if err != nil {
			return fmt.Errorf("createIndex: %w", err)
		}
		if index == nil {
			// Non-indexable blobs are filtered later.
			return fmt.Errorf("not a filesystem")
		}
	}

	fs, err := h.indexedFS(r, ref, index)
	if err != nil {
		return err
	}

	des, err := fs.Everything()
	if err != nil {
		return err
	}

	f := h.renderDirSize(w, r, index.TOC().Csize, ref, index.TOC().Type, types.MediaType(mt), len(des))
	return httpserve.DirList(w, r, httpserve.FS(fs), ref, des, f)
}

func (h *handler) renderDirSize(w http.ResponseWriter, r *http.Request, size int64, ref string, kind string, mediaType types.MediaType, num int) func() error {
	return func() error {
		// This must be a directory because it wasn't part of a filesystem
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
			return err
		}

		header := headerData(ref)

		tarflags := "tar -tv"
		if kind == "tar+gzip" {
			tarflags = "tar -tvz"
		} else if kind == "tar+zstd" {
			tarflags = "tar --zstd -tv"
		}

		ua := r.UserAgent()
		if strings.Contains(ua, "BSD") || strings.Contains(ua, "Mac") {
			tarflags += " | sort -n -r -k5"
		} else {
			tarflags += " | sort -n -r -k3"
		}

		u, err := refToUrl(ref)
		if err != nil {
			return err
		}

		scheme, after, ok := strings.Cut(u, "://")
		if !ok {
			return fmt.Errorf("no scheme in %q", u)
		}
		ref = strings.Replace(ref, "/size", "/"+scheme, 1)

		before, _, ok := strings.Cut(ref, "@")
		if ok {
			dir := scheme + "://" + path.Dir(after)
			if scheme == "file" {
				dir = strings.TrimPrefix(dir, "file://")
			}
			base := path.Base(u)

			index := path.Join(path.Dir(before), "APKINDEX.tar.gz")

			href := fmt.Sprintf("<a class=%q href=%q>%s</a>/<a class=%q href=%q>%s</a>", "mt", index, dir, "mt", ref, base)

			u = href
		}

		if scheme == "file" {
			header.JQ = "cat" + " " + u + " | " + tarflags
		} else if strings.Contains(ref, "apk.cgr.dev/chainguard-private") {
			header.JQ = "curl -sL" + printToken + " " + u + " | " + tarflags
		} else {
			header.JQ = "curl -sL" + " " + u + " | " + tarflags
		}

		if num > httpserve.TooBig {
			header.JQ += fmt.Sprintf(" | head -n %d", httpserve.TooBig)
		}

		return bodyTmpl.Execute(w, header)
	}
}

func (h *handler) addAuth(req *http.Request) error {
	if h.cgauth != nil {
		if req.URL.Host == "apk.cgr.dev" {
			return h.cgauth.AddAuth(req.Context(), req)
		}
	}
	if h.keychain != nil {
		ref := name.MustParseReference("gcr.io/example")
		auth, err := h.keychain.Resolve(ref.Context().Registry)
		if err != nil {
			return fmt.Errorf("keychain resolve: %w", err)
		}
		basic, err := auth.Authorization()
		if err != nil {
			return fmt.Errorf("keychain auth: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+basic.Password)
		return nil
	}

	return nil
}
