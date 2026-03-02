package git

import (
	"bufio"
	"bytes"
	"context"
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

	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/klauspost/compress/gzhttp"
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

	packCache packCache
	packData  memPackData
}

type Option func(h *handler)

func WithUserAgent(ua string) Option {
	return func(h *handler) {
		h.userAgent = ua
	}
}

func New(args []string, opts ...Option) http.Handler {
	h := handler{
		args:      args,
		repos:     map[string]*gitfs.Repo{},
		fsyss:     map[string]fs.FS{},
		commits:   map[string][]byte{},
		packCache: newPackCache(),
	}

	for _, opt := range opts {
		opt(&h)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", h.errHandler(h.renderResponse))
	mux.HandleFunc("/http/", h.errHandler(h.renderFS))
	mux.HandleFunc("/https/", h.errHandler(h.renderFS))
	mux.HandleFunc("/pack/", h.errHandler(h.renderPackObject))

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

	if q := qs.Get("pack"); q != "" {
		u, err := url.PathUnescape(q)
		if err != nil {
			return err
		}
		return h.renderPackOverview(w, r, u)
	}

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

func (h *handler) getOrFetchPack(ctx context.Context, repoURL string) (*PackIndex, string, error) {
	key := cacheKey(repoURL)

	// Try cache first.
	idx, err := h.packCache.GetIndex(ctx, key)
	if err == nil {
		return idx, key, nil
	}

	// Cache miss: fetch the packfile.
	if !strings.Contains(repoURL, "://") {
		repoURL = "https://" + repoURL
	}

	repo, err := gitfs.NewRepo(ctx, repoURL)
	if err != nil {
		return nil, "", fmt.Errorf("NewRepo: %w", err)
	}

	data, err := repo.FetchPack(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("FetchPack: %w", err)
	}

	idx, err = BuildPackIndex(data)
	if err != nil {
		return nil, "", fmt.Errorf("BuildPackIndex: %w", err)
	}

	// Store in cache (best effort).
	if putErr := h.packCache.PutPack(ctx, key, data); putErr != nil {
		log.Printf("pack cache put pack: %v", putErr)
	}
	if putErr := h.packCache.PutIndex(ctx, key, idx); putErr != nil {
		log.Printf("pack cache put index: %v", putErr)
	}

	// Keep packfile data in memory for object detail views.
	h.packData.Put(key, data)

	return idx, key, nil
}

func (h *handler) renderPackOverview(w http.ResponseWriter, r *http.Request, repoURL string) error {
	ctx := r.Context()

	idx, key, err := h.getOrFetchPack(ctx, repoURL)
	if err != nil {
		return err
	}

	repo := strings.TrimPrefix(repoURL, "https://")
	repo = strings.TrimPrefix(repo, "http://")

	if err := headerTmpl.Execute(w, TitleData{"Pack: " + repo}); err != nil {
		return err
	}
	hd := HeaderData{
		Repo:     repo,
		RepoLink: repoURL,
		JQ:       fmt.Sprintf("git verify-pack -v .git/objects/pack/pack-%s.idx", idx.Checksum),
	}
	if err := bodyTmpl.Execute(w, hd); err != nil {
		return err
	}

	// Compute stats.
	nonDelta := 0
	chainLengths := map[int]int{}
	for _, obj := range idx.Objects {
		if obj.Depth == 0 {
			nonDelta++
		} else {
			chainLengths[obj.Depth]++
		}
	}

	// Filter by type if requested.
	filterType := r.URL.Query().Get("type")

	fmt.Fprintf(w, "<pre>\n")
	for _, obj := range idx.Objects {
		if filterType != "" {
			if strings.HasPrefix(filterType, "depth-") {
				var d int
				fmt.Sscanf(filterType, "depth-%d", &d)
				if obj.Depth != d {
					continue
				}
			} else if obj.ResolvedType != filterType && obj.Type != filterType {
				continue
			}
		}
		href := fmt.Sprintf("/pack/%s/%s?key=%s", url.PathEscape(repo), obj.Hash, key)
		hashLink := fmt.Sprintf("<a href=%q>%s</a>", href, obj.Hash)

		if obj.Depth > 0 {
			baseHref := fmt.Sprintf("/pack/%s/%s?key=%s", url.PathEscape(repo), obj.BaseHash, key)
			baseLink := fmt.Sprintf("<a href=%q>%s</a>", baseHref, obj.BaseHash)
			fmt.Fprintf(w, "%s %-6s %d %d %d %d %s\n", hashLink, obj.ResolvedType, obj.Size, obj.EncodedSize, obj.Offset, obj.Depth, baseLink)
		} else {
			fmt.Fprintf(w, "%s %-6s %d %d %d\n", hashLink, obj.ResolvedType, obj.Size, obj.EncodedSize, obj.Offset)
		}
	}

	// Summary.
	fmt.Fprintf(w, "non delta: %d objects\n", nonDelta)
	maxDepth := 0
	for d := range chainLengths {
		if d > maxDepth {
			maxDepth = d
		}
	}
	for d := 1; d <= maxDepth; d++ {
		if c, ok := chainLengths[d]; ok {
			href := fmt.Sprintf("/?pack=%s&type=depth-%d", url.QueryEscape(repoURL), d)
			fmt.Fprintf(w, "chain length = %d: <a href=%q>%d objects</a>\n", d, href, c)
		}
	}

	fmt.Fprintf(w, "</pre>\n")
	fmt.Fprintf(w, footer)
	return nil
}

func (h *handler) renderPackObject(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	// Path: /pack/<repo>/<hash>
	p := strings.TrimPrefix(r.URL.Path, "/pack/")
	lastSlash := strings.LastIndex(p, "/")
	if lastSlash < 0 {
		return fmt.Errorf("invalid pack object path: %s", r.URL.Path)
	}
	repo := p[:lastSlash]
	hash := p[lastSlash+1:]
	key := r.URL.Query().Get("key")
	if key == "" {
		key = cacheKey(repo)
	}

	// Get the index to find the object.
	idx, err := h.packCache.GetIndex(ctx, key)
	if err != nil {
		// Try fetching.
		repoURL := repo
		if !strings.Contains(repoURL, "://") {
			repoURL = "https://" + repoURL
		}
		idx, key, err = h.getOrFetchPack(ctx, repoURL)
		if err != nil {
			return fmt.Errorf("get pack index: %w", err)
		}
	}

	// Find the object by hash.
	var obj *PackObject
	for i := range idx.Objects {
		if idx.Objects[i].Hash == hash {
			obj = &idx.Objects[i]
			break
		}
	}
	if obj == nil {
		return fmt.Errorf("object %s not found in pack", hash)
	}

	// Get the packfile data to decompress the object.
	data := h.packData.Get(key)
	if data == nil {
		data, err = h.packCache.GetPack(ctx, key)
		if err != nil {
			return fmt.Errorf("get pack data: %w", err)
		}
		h.packData.Put(key, data)
	}

	objType, content, err := DecompressObject(data, obj.Hash)
	if err != nil {
		return fmt.Errorf("decompress: %w", err)
	}

	if err := headerTmpl.Execute(w, TitleData{hash[:12] + " - Pack Object"}); err != nil {
		return err
	}
	hd := HeaderData{
		Repo:     repo,
		RepoLink: fmt.Sprintf("/?pack=%s", url.QueryEscape(repo)),
		JQ:       fmt.Sprintf("git cat-file -p %s", hash),
	}
	if err := bodyTmpl.Execute(w, hd); err != nil {
		return err
	}

	fmt.Fprintf(w, "<pre>\n")
	if obj.Type != objType {
		fmt.Fprintf(w, "type:    %s (resolves to %s)\n", obj.Type, objType)
	} else {
		fmt.Fprintf(w, "type:    %s\n", objType)
	}
	fmt.Fprintf(w, "size:    %s (%d bytes)\n", formatBytes(int64(obj.Size)), obj.Size)
	fmt.Fprintf(w, "offset:  %d\n", obj.Offset)
	fmt.Fprintf(w, "encoded: %d bytes\n", obj.EncodedSize)
	if obj.BaseHash != "" {
		baseHref := fmt.Sprintf("/pack/%s/%s?key=%s", url.PathEscape(repo), obj.BaseHash, key)
		fmt.Fprintf(w, "base:    <a href=%q>%s</a> (%s", baseHref, obj.BaseHash, obj.Type)
		if obj.Type == "ofs-delta" {
			fmt.Fprintf(w, ", offset %d", obj.BaseOffset)
		}
		fmt.Fprintf(w, ")\n")
		fmt.Fprintf(w, "depth:   %d\n", obj.Depth)
	}
	fmt.Fprintf(w, "\n")

	// For delta objects, show the raw delta instructions.
	if obj.Type == "ref-delta" || obj.Type == "ofs-delta" {
		rawDelta, err := RawDelta(data, obj.Offset)
		if err == nil {
			deltaInfo, err := ParseDelta(rawDelta)
			if err == nil {
				h.renderDeltaOps(w, deltaInfo, repo, key, idx)
				fmt.Fprintf(w, "\n")
			}
		}
		fmt.Fprintf(w, "<b>--- resolved content (%s) ---</b>\n\n", objType)
	}

	// Render resolved content based on type.
	switch objType {
	case "commit":
		h.renderPackCommit(w, content, repo, key)
	case "tree":
		h.renderPackTree(w, content, repo, key, idx)
	case "blob":
		size := min(int64(len(content)), tooBig)
		esc := &dumbEscaper{buf: bufio.NewWriter(w)}
		io.CopyN(esc, bytes.NewReader(content), size)
		if int64(len(content)) > tooBig {
			fmt.Fprintf(w, "\n... truncated (%s total)", formatBytes(int64(len(content))))
		}
	case "tag":
		h.renderPackTag(w, content, repo, key)
	default:
		fmt.Fprintf(w, "(raw %d bytes)\n", len(content))
	}

	fmt.Fprintf(w, "</pre>\n")
	fmt.Fprintf(w, footer)
	return nil
}

func (h *handler) renderPackCommit(w io.Writer, content []byte, repo, key string) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		hdr, val, ok := strings.Cut(line, " ")
		if !ok {
			fmt.Fprintf(w, "%s\n", htmlEscape(line))
			continue
		}
		switch hdr {
		case "tree", "parent":
			href := fmt.Sprintf("/pack/%s/%s?key=%s", url.PathEscape(repo), val, key)
			fmt.Fprintf(w, "%s <a href=%q>%s</a>\n", hdr, href, val)
		default:
			fmt.Fprintf(w, "%s\n", htmlEscape(line))
		}
	}
}

func (h *handler) renderPackTree(w io.Writer, content []byte, repo, key string, idx *PackIndex) {
	// Build hash lookup.
	hashSet := map[string]bool{}
	for _, obj := range idx.Objects {
		hashSet[obj.Hash] = true
	}

	data := content
	for len(data) > 0 {
		e, size := gitfs.ParseDirEntry(data)
		if size == 0 {
			break
		}
		data = data[size:]

		hashStr := e.Hash.String()
		typeStr := "blob"
		if e.Mode == 0o40000 {
			typeStr = "tree"
		} else if e.Mode == 0o160000 {
			typeStr = "commit"
		}

		name := htmlEscape(string(e.Name))
		if hashSet[hashStr] {
			href := fmt.Sprintf("/pack/%s/%s?key=%s", url.PathEscape(repo), hashStr, key)
			fmt.Fprintf(w, "%06o %s <a href=%q>%s</a>\t%s\n", e.Mode, typeStr, href, hashStr, name)
		} else {
			fmt.Fprintf(w, "%06o %s %s\t%s\n", e.Mode, typeStr, hashStr, name)
		}
	}
}

func (h *handler) renderPackTag(w io.Writer, content []byte, repo, key string) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		hdr, val, ok := strings.Cut(line, " ")
		if !ok {
			fmt.Fprintf(w, "%s\n", htmlEscape(line))
			continue
		}
		switch hdr {
		case "object":
			href := fmt.Sprintf("/pack/%s/%s?key=%s", url.PathEscape(repo), val, key)
			fmt.Fprintf(w, "%s <a href=%q>%s</a>\n", hdr, href, val)
		default:
			fmt.Fprintf(w, "%s\n", htmlEscape(line))
		}
	}
}

func (h *handler) renderDeltaOps(w io.Writer, info *DeltaInfo, repo, key string, idx *PackIndex) {
	// Build hash lookup for linking.
	hashSet := map[string]bool{}
	for _, obj := range idx.Objects {
		hashSet[obj.Hash] = true
	}

	fmt.Fprintf(w, "<b>--- delta instructions ---</b>\n\n")
	fmt.Fprintf(w, "base size:   %s (%d bytes)\n", formatBytes(int64(info.BaseSize)), info.BaseSize)
	fmt.Fprintf(w, "target size: %s (%d bytes)\n", formatBytes(int64(info.TargetSize)), info.TargetSize)
	fmt.Fprintf(w, "operations:  %d\n\n", len(info.Ops))

	for i, op := range info.Ops {
		switch op.Kind {
		case "copy":
			fmt.Fprintf(w, "%4d  <b>copy</b>   base[%d:%d] (%d bytes)\n",
				i, op.Offset, op.Offset+op.Size, op.Size)
		case "insert":
			if isBinary(op.Data) {
				if entries, prefix, suffix := tryParseTreeInsert(op.Data); len(entries) > 0 || len(prefix) > 0 {
					fmt.Fprintf(w, "%4d  <b>insert</b> %d bytes (tree data)\n", i, op.Size)
					if len(prefix) > 0 {
						writeHashFragment(w, prefix, hashSet, repo, key)
					}
					for _, e := range entries {
						hashStr := e.Hash.String()
						typeStr := "blob"
						if e.Mode == 0o40000 {
							typeStr = "tree"
						} else if e.Mode == 0o160000 {
							typeStr = "commit"
						}
						name := htmlEscape(string(e.Name))
						if hashSet[hashStr] {
							href := fmt.Sprintf("/pack/%s/%s?key=%s", url.PathEscape(repo), hashStr, key)
							fmt.Fprintf(w, "        %06o %s <a href=%q>%s</a>\t%s\n", e.Mode, typeStr, href, hashStr, name)
						} else {
							fmt.Fprintf(w, "        %06o %s %s\t%s\n", e.Mode, typeStr, hashStr, name)
						}
					}
					if len(suffix) > 0 {
						writeHashFragment(w, suffix, hashSet, repo, key)
					}
				} else {
					fmt.Fprintf(w, "%4d  <b>insert</b> %d bytes\n", i, op.Size)
					writeHexDump(w, op.Data)
				}
			} else {
				fmt.Fprintf(w, "%4d  <b>insert</b> %d bytes: ", i, op.Size)
				show := op.Data
				truncated := false
				if len(show) > 128 {
					show = show[:128]
					truncated = true
				}
				esc := &dumbEscaper{buf: bufio.NewWriter(w)}
				esc.Write(show)
				if truncated {
					fmt.Fprintf(w, "...")
				}
				fmt.Fprintf(w, "\n")
			}
		}
	}
}

// tryParseTreeInsert tries to interpret binary insert data as tree entry fragments.
// It returns any complete tree entries parsed, plus any leading prefix (trailing
// hash bytes from a previous entry) and trailing suffix that didn't form a complete entry.
func tryParseTreeInsert(data []byte) (entries []gitfs.DirEntry, prefix, suffix []byte) {
	// The insert might start mid-entry — the leading bytes could be the tail
	// of a previous entry's 20-byte hash. Look for the start of a tree entry:
	// an octal digit followed eventually by ' ', name, '\0', 20 bytes.
	start := 0
	for start < len(data) {
		if data[start] >= '1' && data[start] <= '7' {
			// Might be the start of a mode. Try parsing.
			e, size := gitfs.ParseDirEntry(data[start:])
			if size > 0 {
				// Found a valid entry start. Everything before it is prefix.
				if start > 0 {
					prefix = data[:start]
				}
				entries = append(entries, e)
				pos := start + size
				// Parse remaining entries.
				for pos < len(data) {
					e, size := gitfs.ParseDirEntry(data[pos:])
					if size == 0 {
						break
					}
					entries = append(entries, e)
					pos += size
				}
				if pos < len(data) {
					suffix = data[pos:]
				}
				return entries, prefix, suffix
			}
		}
		start++
	}
	// Couldn't parse any entries. Might be a pure hash fragment.
	if len(data) <= 20 {
		return nil, data, nil
	}
	return nil, nil, nil
}

func writeHashFragment(w io.Writer, data []byte, hashSet map[string]bool, repo, key string) {
	if len(data) == 20 {
		hashStr := fmt.Sprintf("%x", data)
		if hashSet[hashStr] {
			href := fmt.Sprintf("/pack/%s/%s?key=%s", url.PathEscape(repo), hashStr, key)
			fmt.Fprintf(w, "        hash <a href=%q>%s</a>\n", href, hashStr)
		} else {
			fmt.Fprintf(w, "        hash %s\n", hashStr)
		}
	} else {
		fmt.Fprintf(w, "        (%d bytes) %x\n", len(data), data)
	}
}

func isBinary(data []byte) bool {
	for _, b := range data {
		if b == 0 || b >= 0x7f {
			return true
		}
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			return true
		}
	}
	return false
}

func writeHexDump(w io.Writer, data []byte) {
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		line := data[i:end]

		// Offset.
		fmt.Fprintf(w, "        %04x  ", i)

		// Hex bytes.
		for j, b := range line {
			if j == 8 {
				fmt.Fprintf(w, " ")
			}
			fmt.Fprintf(w, "%02x ", b)
		}
		// Pad if short line.
		for j := len(line); j < 16; j++ {
			if j == 8 {
				fmt.Fprintf(w, " ")
			}
			fmt.Fprintf(w, "   ")
		}

		// ASCII.
		fmt.Fprintf(w, " |")
		for _, b := range line {
			if b >= 0x20 && b < 0x7f {
				fmt.Fprintf(w, "%c", b)
			} else {
				fmt.Fprintf(w, ".")
			}
		}
		fmt.Fprintf(w, "|\n")
	}
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
