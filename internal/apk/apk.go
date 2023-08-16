package apk

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/logs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	httpserve "github.com/jonjohnsonjr/dag.dev/internal/forks/http"
	"github.com/jonjohnsonjr/dag.dev/internal/soci"
	"github.com/jonjohnsonjr/dag.dev/internal/xxd"
	hgzip "github.com/nanmu42/gzip"
	"golang.org/x/oauth2"
)

// We should not buffer blobs greater than 4MB
const tooBig = 1 << 25
const respTooBig = 1 << 25

type handler struct {
	mux       http.Handler
	keychain  authn.Keychain
	userAgent string

	// digest -> remote.desc
	manifests map[string]*remote.Descriptor

	// reg.String() -> ping resp
	pings map[string]*transport.PingResp

	tocCache   cache
	indexCache cache

	sync.Mutex
	sawTags map[string][]string

	oauth *oauth2.Config
}

type Option func(h *handler)

func WithUserAgent(ua string) Option {
	return func(h *handler) {
		h.userAgent = ua
	}
}

func New(opts ...Option) http.Handler {
	h := handler{
		manifests:  map[string]*remote.Descriptor{},
		pings:      map[string]*transport.PingResp{},
		sawTags:    map[string][]string{},
		tocCache:   buildTocCache(),
		indexCache: buildIndexCache(),
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

	// Try to detect mediaType.
	mux.HandleFunc("/blob/", h.errHandler(h.renderFS))

	h.mux = hgzip.DefaultHandler().WrapHandler(mux)

	return &h
}

func splitFsURL(p string) (string, string, error) {
	for _, prefix := range []string{"/fs/", "/layers/", "/https/", "/http/", "/blob/", "/cache/", "/size/"} {
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(p, prefix), prefix, nil
		}
	}

	return "", "", fmt.Errorf("unexpected path: %v", p)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.oauth == nil {
		// Cloud run already logs this stuff, don't log extra.
		log.Printf("%v", r.URL)

		start := time.Now()
		defer func() {
			log.Printf("%v (%s)", r.URL, time.Since(start))
		}()
	}

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

	// Cache landing page for 5 minutes.
	// TODO: Uncomment this.
	// w.Header().Set("Cache-Control", "max-age=300")
	w.Write([]byte(landingPage))

	return nil
}

func renderOctets(w http.ResponseWriter, r *http.Request, b []byte) error {
	fmt.Fprintf(w, "<pre>")
	if _, err := io.Copy(xxd.NewWriter(w, int64(len(b))), bytes.NewReader(b)); err != nil {
		return err
	}
	fmt.Fprintf(w, "</pre>")

	return nil
}

func (h *handler) renderContent(w http.ResponseWriter, r *http.Request, ref string, b []byte, output *jsonOutputter, u url.URL) error {
	switch r.URL.Query().Get("render") {
	case "raw":
		fmt.Fprintf(w, "<pre>")
		if _, err := w.Write(b); err != nil {
			return err
		}
		fmt.Fprintf(w, "</pre>")
	case "x509":
		return renderx509(w, b)
	case "cert":
		return renderCert(w, b, u)
	case "der":
		return renderDer(w, b)
	case "xxd":
		return renderOctets(w, r, b)
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
	mt := r.URL.Query().Get("mt")

	// Allow this to be cached for an hour.
	w.Header().Set("Cache-Control", "max-age=3600, immutable")

	httpserve.ServeContent(w, r, "", time.Time{}, blob, func(w http.ResponseWriter, ctype string) error {
		// Kind at this poin can be "gzip", "zstd" or ""
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
			return err
		}
		desc := v1.Descriptor{
			MediaType: types.MediaType(mt),
			Size:      blob.Size(),
		}
		if size := r.URL.Query().Get("size"); size != "" {
			if parsed, err := strconv.ParseInt(size, 10, 64); err == nil {
				desc.Size = parsed
			}
		}
		header := headerData(ref, desc)

		before, _, ok := strings.Cut(ref, "@")
		if ok {
			u := "https://" + strings.TrimPrefix(before, "/https/")
			header.JQ = "curl -L" + " " + u
			if kind == "zstd" {
				header.JQ += " | zstd -d"
			} else if kind == "gzip" {
				header.JQ += " | gunzip"
			}
			if blob.size < 0 || blob.size > httpserve.TooBig {
				header.JQ += fmt.Sprintf(" | head -c %d", httpserve.TooBig)
			}
			if !strings.HasPrefix(ctype, "text/") && !strings.Contains(ctype, "json") {
				header.JQ += " | xxd"
			}
		}

		return bodyTmpl.Execute(w, header)
	})

	return nil
}

func (h *handler) getEtag(u string) (string, error) {
	etag, err := h.headUrl(u)
	if err != nil {
		return "", fmt.Errorf("resolving etag: %w", err)
	}

	if unquoted, err := strconv.Unquote(strings.TrimPrefix(etag, "W/")); err == nil {
		etag = unquoted
	}

	// TODO: Consider caring about W/"..." vs "..."?
	etagHex := hex.EncodeToString([]byte(etag))

	if _, err := hex.DecodeString(etag); err == nil {
		etagHex = etag
	}

	return etagHex, nil
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
		log.Printf("qss = %q", qss)
	}
	depends, ok := qs["depend"]
	if ok {
		for i, dep := range depends {
			depends[i] = url.QueryEscape(dep)
		}
		qss += "&depend=" + strings.Join(depends, "&depend=")
		log.Printf("qss = %q", qss)
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
			log.Printf("%q != %q", redir, r.URL.Path)
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
		fs, err := h.indexedFS(w, r, ref, index)
		if err != nil {
			return err
		}

		if strings.HasSuffix(r.URL.Path, "APKINDEX") {
			filename := strings.TrimPrefix(r.URL.Path, "/")
			log.Printf("rendering APKINDEX: %q", filename)
			rc, err := fs.Open(filename)
			if err != nil {
				return fmt.Errorf("open(%q): %w", filename, err)
			}
			defer rc.Close()

			return h.renderIndex(w, r, rc, ref)
		} else if strings.HasSuffix(r.URL.Path, ".spdx.json") {
			filename := strings.TrimPrefix(r.URL.Path, "/")
			log.Printf("rendering SBOM: %q", filename)
			rc, err := fs.Open(filename)
			if err != nil {
				return fmt.Errorf("open(%q): %w", filename, err)
			}
			defer rc.Close()

			return h.renderSBOM(w, r, rc, ref)
		} else if strings.HasSuffix(r.URL.Path, "/.PKGINFO") {
			filename := strings.TrimPrefix(r.URL.Path, "/")
			log.Printf("rendering .PKGINFO: %q", filename)
			rc, err := fs.Open(filename)
			if err != nil {
				return fmt.Errorf("open(%q): %w", filename, err)
			}
			defer rc.Close()

			return h.renderPkgInfo(w, r, rc, ref)
		} else if strings.Contains(r.URL.Path, ".apk@") {
		}

		log.Printf("serving http from cache")
		httpserve.FileServer(httpserve.FS(fs)).ServeHTTP(w, r)
		return nil
	}

	// Determine if this is actually a filesystem thing.
	blob, prefix, err := h.fetchBlob(w, r)
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

	return nil
}

func getUpstreamURL(r *http.Request) (string, error) {
	return refToUrl(r.URL.Path)
}

func (h *handler) indexedFS(w http.ResponseWriter, r *http.Request, ref string, index soci.Index) (*soci.SociFS, error) {
	toc := index.TOC()
	if toc == nil {
		return nil, fmt.Errorf("this should not happen")
	}
	mt := toc.MediaType

	cachedUrl, err := getUpstreamURL(r)
	if err != nil {
		return nil, err
	}

	blob := LazyBlob(cachedUrl, toc.Csize)
	prefix := strings.TrimPrefix(ref, "/")
	fs := soci.FS(index, blob, prefix, ref, respTooBig, types.MediaType(mt), renderHeader)

	return fs, nil
}

func (h *handler) jq(output *jsonOutputter, b []byte, r *http.Request, header *HeaderData) ([]byte, error) {
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

func headerData(ref string, desc v1.Descriptor) *HeaderData {
	return &HeaderData{
		CosignTags:       []CosignTag{},
		Descriptor:       &desc,
		Handler:          handlerForMT(string(desc.MediaType)),
		EscapedMediaType: url.QueryEscape(string(desc.MediaType)),
		MediaTypeLink:    getLink(string(desc.MediaType)),
	}
}

func refToUrl(p string) (string, error) {
	scheme := "https://"
	if strings.HasPrefix(p, "/http/") {
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

func renderHeader(w http.ResponseWriter, fname string, prefix string, ref string, kind string, mediaType types.MediaType, size int64, f httpserve.File, ctype string) error {
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
	} else {
		if !stat.IsDir() {
			logs.Debug.Printf("not a tar header or directory")
		}
	}

	tarflags := "tar -Ox "
	if kind == "tar+gzip" {
		tarflags = "tar -Oxz "
	} else if kind == "tar+zstd" {
		tarflags = "tar --zstd -Ox "
	}

	// TODO: Use hash if we have it?
	// hash, err := v1.NewHash(ref.Identifier())
	// if err != nil {
	// 	return err
	// }

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

	desc := v1.Descriptor{
		Size: size,
		// Digest:    hash,
		MediaType: mediaType,
	}

	header := headerData(ref, desc)
	if strings.Contains(ref, ".apk@") {
		if _, after, ok := strings.Cut(prefix, "/"); ok {
			href := path.Join("/size", after)
			header.SizeLink = href
		}
	}

	if stat.IsDir() {
		tarflags = "tar -tv "
		if kind == "tar+gzip" {
			tarflags = "tar -tvz "
		} else if kind == "tar+zstd" {
			tarflags = "tar --zstd -tv "
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
	base := path.Base(u)

	before, _, ok := strings.Cut(ref, "@")
	if !ok {
		return fmt.Errorf("no @ in apk")
	}

	index := path.Join(path.Dir(before), "APKINDEX.tar.gz")

	href := fmt.Sprintf("<a class=%q href=%q>%s</a>/<a class=%q href=%q>%s</a>", "mt", index, dir, "mt", ref, base)

	u = href

	header.JQ = "curl -L" + " " + u + " | " + tarflags + " " + filelink

	if !stat.IsDir() {
		if stat.Size() > httpserve.TooBig {
			header.JQ += fmt.Sprintf(" | head -c %d", httpserve.TooBig)
		}
		if !strings.HasPrefix(ctype, "text/") && !strings.Contains(ctype, "json") {
			header.JQ += " | xxd"
		}
	}
	// header.SizeLink = fmt.Sprintf("/size/%s?mt=%s&size=%d", ref.Context().Digest(hash.String()).String(), mediaType, int64(size))

	return bodyTmpl.Execute(w, header)
}

// server.go
var htmlReplacer = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	// "&#34;" is shorter than "&quot;".
	`"`, "&#34;",
	// "&#39;" is shorter than "&apos;" and apos was not in HTML until HTML5.
	"'", "&#39;",
)

func htmlEscape(s string) string {
	return htmlReplacer.Replace(s)
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

	header := headerData(ref, v1.Descriptor{})

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
		u := "https://" + strings.TrimPrefix(before, "/https/")
		scheme, after, ok := strings.Cut(u, "://")
		if !ok {
			return fmt.Errorf("no scheme in %q", u)
		}
		dir := scheme + "://" + path.Dir(after)
		base := path.Base(u)

		index := path.Join(path.Dir(before), "APKINDEX.tar.gz")

		href := fmt.Sprintf("<a class=%q href=%q>%s</a>/<a class=%q href=%q>%s</a>", "mt", index, dir, "mt", ref, base)

		u = href
		header.JQ = "curl -L" + " " + u + " | tar -Oxz " + filelink
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
		fmt.Fprintf(w, footer)

		return nil
	}

	// TODO: Can we do this in a streaming way?
	input, err := ioutil.ReadAll(io.LimitReader(in, tooBig))
	if err != nil {
		return err
	}

	// Mutates header for bodyTmpl.
	b, err := h.jq(output, input, r, header)
	if err != nil {
		return fmt.Errorf("h.jq: %w", err)
	}

	if err := bodyTmpl.Execute(w, header); err != nil {
		return fmt.Errorf("bodyTmpl: %w", err)
	}

	if err := h.renderContent(w, r, ref, b, output, *r.URL); err != nil {
		if r.URL.Query().Get("render") == "xxd" {
			return fmt.Errorf("renderContent: %w", err)
		}

		r.URL.Query().Set("render", "xxd")
		fmt.Fprintf(w, "NOTE: failed to render: %v\n", err)
		if err := renderOctets(w, r, b); err != nil {
			return fmt.Errorf("renderContent fallback: %w", err)
		}
	}

	fmt.Fprintf(w, footer)

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
		filename := strings.TrimPrefix(r.URL.Path, "")
		log.Printf("opening %q", filename)
		rc, err := fs.Open(filename)
		if err != nil {
			return fmt.Errorf("open(%q): %w", filename, err)
		}
		defer rc.Close()

		if err := h.renderIndex(w, r, rc, ref); err != nil {
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

	fs, err := h.indexedFS(w, r, ref, index)
	if err != nil {
		return err
	}

	des, err := fs.Everything()
	if err != nil {
		return err
	}

	f := renderDirSize(w, r, index.TOC().Csize, ref, index.TOC().Type, types.MediaType(mt), len(des))
	return httpserve.DirList(w, r, ref, des, f)
}

func renderDirSize(w http.ResponseWriter, r *http.Request, size int64, ref string, kind string, mediaType types.MediaType, num int) func() error {
	return func() error {
		// This must be a directory because it wasn't part of a filesystem
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
			return err
		}

		desc := v1.Descriptor{
			Size: size,
		}
		header := headerData(ref, desc)

		tarflags := "tar -tv "
		if kind == "tar+gzip" {
			tarflags = "tar -tvz "
		} else if kind == "tar+zstd" {
			tarflags = "tar --zstd -tv "
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
			base := path.Base(u)

			index := path.Join(path.Dir(before), "APKINDEX.tar.gz")

			href := fmt.Sprintf("<a class=%q href=%q>%s</a>/<a class=%q href=%q>%s</a>", "mt", index, dir, "mt", ref, base)

			u = href
		}

		header.JQ = "curl -L" + " " + u + " | " + tarflags

		if num > httpserve.TooBig {
			header.JQ += fmt.Sprintf(" | head -n %d", httpserve.TooBig)
		}

		return bodyTmpl.Execute(w, header)
	}
}
