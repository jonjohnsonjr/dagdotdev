package git

import (
	"bufio"
	"bytes"
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
	"strings"
	"sync"

	"github.com/jonjohnsonjr/dagdotdev/internal/forks/rsc.io/gitfs"
	"golang.org/x/exp/maps"

	"github.com/klauspost/compress/gzhttp"
)

// We should not buffer blobs greater than 2MB
const tooBig = 1024 * 1024
const respTooBig = 1 << 25

type handler struct {
	mux       http.Handler
	userAgent string

	args []string

	sync.Mutex
	repos   map[string]*gitfs.Repo
	commits map[string][]byte
	fsyss   map[string]fs.FS
}

type Option func(h *handler)

func WithUserAgent(ua string) Option {
	return func(h *handler) {
		h.userAgent = ua
	}
}

func New(args []string, opts ...Option) http.Handler {
	h := handler{
		args:    args,
		repos:   map[string]*gitfs.Repo{},
		fsyss:   map[string]fs.FS{},
		commits: map[string][]byte{},
	}

	for _, opt := range opts {
		opt(&h)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", h.errHandler(h.renderResponse))
	mux.HandleFunc("/http/", h.errHandler(h.renderFS))
	mux.HandleFunc("/https/", h.errHandler(h.renderFS))

	h.mux = gzhttp.GzipHandler(mux)

	return &h
}

func splitFsURL(p string) (string, string, error) {
	for _, prefix := range []string{"/fs/", "/https/", "/http/", "/file/"} {
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(p, prefix), prefix, nil
		}
	}

	return "", "", fmt.Errorf("unexpected path: %v", p)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

		if !strings.Contains(u, "@") {
			return h.renderRefs(w, r, u)
		}

		return h.renderCommit(w, r, u)
	}

	fmt.Fprintf(w, landing)
	return nil
}

func (h *handler) renderCommit(w http.ResponseWriter, r *http.Request, u string) error {
	ctx := r.Context()

	u, digest, ok := strings.Cut(u, "@")
	if !ok {
		return fmt.Errorf("no @: %q", u)
	}

	p := u
	if before, after, ok := strings.Cut(u, "://"); ok {
		p = path.Join(before, after)
	}

	var err error
	h.Lock()
	repo, ok := h.repos[u]
	h.Unlock()
	if !ok {
		repo, err = gitfs.NewRepo(ctx, u)
		if err != nil {
			return fmt.Errorf("NewRepo: %w", err)
		}
		h.Lock()
		h.repos[u] = repo
		h.Unlock()
	}

	resolved, err := repo.Resolve(ctx, digest)
	if err != nil {
		return fmt.Errorf("Resolve(%q): %w", digest, err)
	}

	var cdata []byte
	h.Lock()
	fsys, ok := h.fsyss[resolved.String()]
	cdata = h.commits[resolved.String()]
	h.Unlock()
	if !ok {
		fsys, cdata, err = repo.CloneHash(ctx, resolved)
		if err != nil {
			return fmt.Errorf("Clone: %w", err)
		}
		h.Lock()
		h.fsyss[resolved.String()] = fsys
		h.commits[resolved.String()] = cdata
		h.Unlock()
	}

	if err := headerTmpl.Execute(w, TitleData{u}); err != nil {
		return err
	}

	hd := headerData(r, u, resolved.String(), "")
	hd.JQ = "git cat-file -p " + resolved.String()

	if err := bodyTmpl.Execute(w, hd); err != nil {
		return err
	}

	fmt.Fprintf(w, "<pre>\n")
	scanner := bufio.NewScanner(bytes.NewReader(cdata))
	for scanner.Scan() {
		line := scanner.Text()
		hdr, val, ok := strings.Cut(line, " ")
		if !ok {
			fmt.Fprintf(w, "%s\n", line)
			continue
		}

		switch hdr {
		case "tree":
			// TODO: We should use val here but we fetch every time.
			href := fmt.Sprintf("%s@%s/", p, resolved.String())

			fmt.Fprintf(w, "%s <a href=%q>%s<a>\n", hdr, href, val)
		case "parent":
			href := fmt.Sprintf("/?url=%s@%s", u, val)
			fmt.Fprintf(w, "%s <a href=%q>%s<a>\n", hdr, href, val)
		default:
			fmt.Fprintf(w, "%s\n", line)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	fmt.Fprintf(w, "</pre>\n")
	fmt.Fprintf(w, footer)

	return nil
}

func (h *handler) renderRefs(w http.ResponseWriter, r *http.Request, u string) error {
	ctx := r.Context()

	if !strings.Contains(u, "://") {
		u = "https://" + u
	}

	var err error
	h.Lock()
	repo, ok := h.repos[u]
	h.Unlock()
	if !ok {
		repo, err = gitfs.NewRepo(ctx, u)
		if err != nil {
			return fmt.Errorf("NewRepo: %w", err)
		}
		h.Lock()
		h.repos[u] = repo
		h.Unlock()
	}

	refs, err := repo.Refs(ctx)
	if err != nil {
		return fmt.Errorf("Refs: %w", err)
	}

	if err := headerTmpl.Execute(w, TitleData{u}); err != nil {
		return err
	}
	hd := HeaderData{
		Repo:     strings.TrimPrefix(u, "https://"),
		RepoLink: u,
		JQ:       "git ls-remote",
	}

	if strings.HasPrefix(u, "https://github.com") {
		// We don't have a way to show all refs, so just link to branches.
		hd.RepoLink = fmt.Sprintf("%s/branches", strings.TrimSuffix(hd.RepoLink, "/"))
	}

	if err := bodyTmpl.Execute(w, hd); err != nil {
		return err
	}
	fmt.Fprintf(w, "<pre>\n")
	fmt.Fprintf(w, "From %s\n", u)
	for _, ref := range refs {
		href := fmt.Sprintf("/?url=%s@%s", u, ref.Hash.String())
		refhref := fmt.Sprintf("/?url=%s@%s", u, ref.Name)
		fmt.Fprintf(w, "<a href=%q>%s</a>\t<a class=\"mt\" href=%q>%s<a>\n", href, ref.Hash.String(), refhref, ref.Name)
	}
	fmt.Fprintf(w, "</pre>\n")
	fmt.Fprintf(w, footer)
	return nil
}

func (h *handler) renderFS(w http.ResponseWriter, r *http.Request) error {
	u, err := getUpstreamURL(r)
	if err != nil {
		return err
	}

	p, root, err := splitFsURL(r.URL.Path)
	if err != nil {
		return err
	}

	before, after, ok := strings.Cut(p, "@")
	if !ok {
		return fmt.Errorf("no @: %q", p)
	}

	digest, subpath, ok := strings.Cut(after, "/")
	if ok {
		p = before + "@" + digest
	} else {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusFound)
		return nil
	}

	ctx := r.Context()

	h.Lock()
	repo, ok := h.repos[u]
	h.Unlock()
	if !ok {
		repo, err = gitfs.NewRepo(ctx, u)
		if err != nil {
			return fmt.Errorf("NewRepo: %w", err)
		}
		h.Lock()
		h.repos[u] = repo
		h.Unlock()
	}

	hash, err := repo.Resolve(ctx, digest)
	if err != nil {
		return fmt.Errorf("Resolve(%q): %w", digest, err)
	}

	if digest != hash.String() {
		redir := root + before + "@" + hash.String() + "/" + subpath
		log.Printf("redirected to resolved hash %q", redir)
		http.Redirect(w, r, redir, http.StatusFound)
		return nil
	}

	prefix := strings.TrimPrefix(root, "/") + p
	log.Printf("prefix=%q", prefix)

	var cdata []byte
	h.Lock()
	fsys, ok := h.fsyss[hash.String()]
	cdata = h.commits[hash.String()]
	h.Unlock()
	if !ok {
		fsys, cdata, err = repo.CloneHash(ctx, hash)
		if err != nil {
			return fmt.Errorf("Clone: %w", err)
		}
		h.Lock()
		h.fsyss[hash.String()] = fsys
		h.commits[hash.String()] = cdata
		h.Unlock()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := headerTmpl.Execute(w, TitleData{u}); err != nil {
		return err
	}
	return h.serve(w, r, fsys, u, hash, prefix)
}

func (h *handler) serve(w http.ResponseWriter, r *http.Request, fsys fs.FS, u string, hash gitfs.Hash, prefix string) error {
	name := r.URL.Path
	if !strings.HasPrefix(name, "/") {
		name = "/" + name
	}
	name = strings.TrimPrefix(path.Clean(name), "/")

	p := strings.TrimPrefix(name, prefix)
	p = strings.TrimPrefix(p, "/")

	f, err := fsys.Open(name)
	if err != nil {
		return fmt.Errorf("Open(%q): %w", name, err)
	}
	defer f.Close()
	d, err := f.Stat()
	if err != nil {
		return fmt.Errorf("Stat(%q): %w", name, err)
	}

	if d.IsDir() && !strings.HasSuffix(r.URL.Path, "/") {
		redir := r.URL.Path + "/"
		log.Printf("redirected to resolved hash %q", redir)
		http.Redirect(w, r, redir, http.StatusFound)
		return nil
	}

	hd := headerData(r, u, hash.String(), name)

	if tfs, ok := fsys.(interface{ Tree() string }); ok {
		hd.JQ = "git cat-file -p " + tfs.Tree()

		if strings.HasPrefix(u, "https://github.com") {
			hd.RepoLink = fmt.Sprintf("%s/tree/%s", strings.TrimSuffix(u, ".git"), hash.String())
		}
		if sys := d.Sys(); sys != nil {
			if e, ok := sys.(*gitfs.DirEntry); ok && e != nil {
				if d.Name() == "." {
					hd.Path = ""
				} else {
					// TODO: Revisit this.
					hd.Path = p
					hd.RepoLink = fmt.Sprintf("%s/%s", hd.RepoLink, p)
				}
			}
		}
	}

	if sys := d.Sys(); sys != nil {
		if e, ok := sys.(*gitfs.DirEntry); ok && e != nil {
			hd.JQ = "git cat-file -p " + e.Hash.String()
		}
	}

	if !d.IsDir() && d.Size() > tooBig {
		hd.JQ = fmt.Sprintf("%s | head -c %d", hd.JQ, tooBig)
	}

	if err := bodyTmpl.Execute(w, hd); err != nil {
		return err
	}

	fmt.Fprintf(w, "<pre>\n")
	if d.IsDir() {
		fdir, ok := f.(fs.ReadDirFile)
		if !ok {
			return fmt.Errorf("not a ReadDirFile: %T", f)
		}

		des, err := fdir.ReadDir(-1)
		if err != nil {
			return fmt.Errorf("ReadDir: %w", err)
		}

		var modules map[string]string

		for _, de := range des {
			stat, err := de.Info()
			if err != nil {
				return fmt.Errorf("Stat: %w", err)
			}
			if sys := stat.Sys(); sys != nil {
				e, ok := sys.(*gitfs.DirEntry)
				if !ok {
					return fmt.Errorf("not a gitfs.DirEntry: %T", sys)
				}

				url := url.URL{Path: strings.TrimPrefix(string(e.Name), "/")}
				href := url.String()
				anchor := htmlReplacer.Replace(string(e.Name))
				if e.Mode == 0o160000 {
					// TODO: Do this once per commit?
					if len(modules) == 0 {
						maybeSubmodules, err := fsys.Open(path.Join(prefix, ".gitmodules"))
						if err == nil {
							modules, err = parseSubmodules(maybeSubmodules)
							if err != nil {
								return fmt.Errorf("parseSubmodules: %w", err)
							}
						}
					}

					mod, ok := modules[path.Join(p, de.Name())]
					if !ok {
						return fmt.Errorf("no module for %q, have %v", p, maps.Keys(modules))
					}

					href := fmt.Sprintf("/?url=%s@%s", mod, e.Hash)
					fmt.Fprintf(w, "%06o commit %s\t<a href=%q>%s</a>\n", e.Mode, e.Hash, href, anchor)
				} else if e.Mode == 0o40000 {
					fmt.Fprintf(w, "%06o tree %s\t<a href=%q>%s</a>\n", e.Mode, e.Hash, href+"/", anchor)
				} else {
					fmt.Fprintf(w, "%06o blob %s\t<a href=%q>%s</a>\n", e.Mode, e.Hash, href, anchor)
				}
			}
		}
	} else {
		size := min(d.Size(), tooBig)
		w := &dumbEscaper{buf: bufio.NewWriter(w)}
		if _, err := io.CopyN(w, f, size); err != nil {
			return err
		}
	}
	fmt.Fprintf(w, "</pre>\n")
	fmt.Fprintf(w, footer)

	return nil
}

func parseSubmodules(r io.Reader) (map[string]string, error) {
	scanner := bufio.NewScanner(r)
	submodules := map[string]string{}
	u, p := "", ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "path") {
			if _, after, ok := strings.Cut(line, "="); ok {
				p = strings.TrimSpace(after)
			}
		} else if strings.HasPrefix(line, "url") {
			if _, after, ok := strings.Cut(line, "="); ok {
				u = strings.TrimSpace(after)
			}
		}

		if u != "" && p != "" {
			if strings.HasPrefix(u, "git://github.com") {
				u = strings.Replace(u, "git://", "https://", 1)
			}
			submodules[p] = u
			u, p = "", ""
		}
	}
	return submodules, scanner.Err()
}

func headerData(r *http.Request, u, ref, p string) HeaderData {
	_, repo, _ := strings.Cut(u, "://")

	hd := HeaderData{
		Repo:     repo,
		RepoLink: u,
	}

	if ref != "" {
		if strings.HasPrefix(u, "https://github.com") {
			hd.RepoLink = fmt.Sprintf("%s/commit/%s", strings.TrimSuffix(hd.RepoLink, ".git"), ref)
		}

		hd.Ref = ref
		hd.RefLink = fmt.Sprintf("/?url=%s@%s", u, ref)

		if p != "" {
			hd.Path = p
			hd.PathLink = path.Dir(strings.TrimSuffix(r.URL.Path, "/"))
		}
	}

	return hd
}

func getUpstreamURL(r *http.Request) (string, error) {
	return refToUrl(r.URL.Path)
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
	}
	before, _, ok := strings.Cut(p, "@")
	if !ok {
	}
	u, err := url.PathUnescape(before)
	if err != nil {
		return "", err
	}
	u = scheme + u

	return strings.TrimSuffix(u, "/"), nil
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
