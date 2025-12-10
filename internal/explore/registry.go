package explore

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/authn"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/logs"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/v1"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/jonjohnsonjr/dagdotdev/internal/verify"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

func isDockerHub(repo name.Repository) bool {
	reg := repo.Registry.String()
	return reg == "index.docker.io" || reg == "docker.io"
}

// don't cache potentially private manifests
func allowCache(r *http.Request, ref name.Reference) bool {
	if _, err := r.Cookie("access_token"); err == nil {
		return !isGoogle(ref.Context().Registry.String())
	}
	return true
}

func (h *handler) remoteOptions(w http.ResponseWriter, r *http.Request, repo string) []remote.Option {
	ctx := r.Context()

	// TODO: Set timeout.
	opts := []remote.Option{}
	opts = append(opts, remote.WithContext(ctx))

	auth := authn.Anonymous
	if h.keychain != nil {
		ref, err := name.NewRepository(repo)
		if err == nil {
			maybeAuth, err := h.keychain.Resolve(ref)
			if err == nil {
				auth = maybeAuth
			} else {
				logs.Debug.Printf("Resolve(%q) = %v", repo, err)
			}
		} else {
			logs.Debug.Printf("NewRepository(%q) = %v", repo, err)
		}
	}

	parsed, err := name.NewRepository(repo)
	if err == nil && isGoogle(parsed.Registry.String()) {
		if at, err := r.Cookie("access_token"); err == nil {
			tok := &oauth2.Token{
				AccessToken: at.Value,
				Expiry:      at.Expires,
			}
			if rt, err := r.Cookie("refresh_token"); err == nil {
				tok.RefreshToken = rt.Value
			}
			if h.oauth != nil {
				ts := h.oauth.TokenSource(r.Context(), tok)
				auth = google.NewTokenSourceAuthenticator(ts)
			}

		}
	}

	opts = append(opts, remote.WithAuth(auth))

	if t, err := h.transportFromCookie(w, r, repo, auth); err != nil {
		log.Printf("failed to get transport from cookie: %v", err)
	} else {
		opts = append(opts, remote.WithTransport(t))
	}

	if n := r.URL.Query().Get("n"); n != "" {
		size, err := strconv.ParseInt(n, 10, 64)
		if err != nil {
			log.Printf("n = %s, err: %v", n, err)
		} else {
			opts = append(opts, remote.WithPageSize(int(size)))
		}
	}
	if next := r.URL.Query().Get("next"); next != "" {
		opts = append(opts, remote.WithNext(next))
	}

	return opts
}

func (h *handler) fetchManifest(w http.ResponseWriter, r *http.Request, ref name.Reference) (*remote.Descriptor, error) {
	opts := h.remoteOptions(w, r, ref.Context().Name())
	opts = append(opts, remote.WithMaxSize(tooBig))

	if _, ok := ref.(name.Digest); !ok && isDockerHub(ref.Context()) {
		// To avoid DockerHub rate limits, HEAD and rewrite ref to be a name.Digest.
		desc, err := remote.Head(ref, opts...)
		if err != nil {
			return nil, err
		}
		ref = ref.Context().Digest(desc.Digest.String())
	}
	if _, ok := ref.(name.Digest); ok {
		if desc, ok := h.manifests[ref.Identifier()]; ok {
			return desc, nil
		}
	}

	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, err
	}
	if allowCache(r, ref) {
		h.manifests[desc.Digest.String()] = desc
	}
	return desc, nil
}

// Unused, left to make it easy to test registries.
func (h *handler) fetchManifestAndReferrersTag(w http.ResponseWriter, r *http.Request, ref name.Reference, opts []remote.Option) (desc *remote.Descriptor, err error) {
	var g errgroup.Group
	g.Go(func() error {
		desc, err = h.fetchManifest(w, r, ref)
		return err
	})
	if dig, ok := ref.(name.Digest); ok {
		g.Go(func() error {
			if _, ok := h.getTags(ref.Context()); ok {
				return nil
			}
			fallback := strings.ReplaceAll(dig.Identifier(), ":", "-")
			ref := ref.Context().Tag(fallback)
			if _, err := remote.Head(ref, opts...); err != nil {
				log.Printf("fallback check: %v", err)
				return nil
			}

			h.Lock()
			defer h.Unlock()
			if _, ok := h.sawTags[ref.Context().String()]; ok {
				return nil
			}
			h.sawTags[ref.Context().String()] = []string{fallback}

			return nil
		})
	}
	err = g.Wait()
	return
}

func (h *handler) listTags(w http.ResponseWriter, r *http.Request, ref name.Repository, repo string) (tags *remote.Tags, err error) {
	defer func() {
		if tags != nil {
			h.Lock()
			h.sawTags[ref.String()] = tags.Tags
			h.Unlock()
		}
	}()

	qs := r.URL.Query()
	opts := h.remoteOptions(w, r, repo)
	if qs.Get("n") != "" {
		return remote.ListPage(ref, qs.Get("next"), opts...)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	opts = append(opts, remote.WithContext(ctx))

	return remote.List(ref, opts...)
}

func (h *handler) listCatalog(w http.ResponseWriter, r *http.Request, ref name.Repository, repo string) (*remote.Catalogs, error) {
	opts := h.remoteOptions(w, r, repo)
	if r.URL.Query().Get("n") != "" {
		return remote.CatalogPage(ref.Registry, r.URL.Query().Get("next"), opts...)
	}

	repos, err := remote.Catalog(r.Context(), ref.Registry, h.remoteOptions(w, r, repo)...)
	return &remote.Catalogs{
		Repos: repos,
	}, err
}

// Fetch blob from registry or URL.
func (h *handler) fetchBlob(w http.ResponseWriter, r *http.Request) (*sizeBlob, string, error) {
	path, root, err := splitFsURL(r.URL.Path)
	if err != nil {
		return nil, "", err
	}

	expectedSize := int64(0)
	qsize := r.URL.Query().Get("size")
	if qsize != "" {
		if sz, err := strconv.ParseInt(qsize, 10, 64); err != nil {
			log.Printf("wtf? %q size=%q", path, qsize)
		} else {
			expectedSize = sz
		}
	}

	chunks := strings.SplitN(path, "@", 2)
	if len(chunks) != 2 {
		return nil, "", fmt.Errorf("not enough chunks: %s", path)
	}
	// 71 = len("sha256:") + 64
	if len(chunks[1]) < 71 {
		return nil, "", fmt.Errorf("second chunk too short: %s", chunks[1])
	}

	digest := ""
	if strings.HasPrefix(chunks[1], "sha256:") {
		digest = chunks[1][:71]
	} else if strings.HasPrefix(chunks[1], "sha512:") {
		digest = chunks[1][:135]
	}

	ref := strings.Join([]string{chunks[0], digest}, "@")
	if ref == "" {
		return nil, "", fmt.Errorf("bad ref: %s", path)
	}

	if root == "/http/" || root == "/https/" {
		return h.fetchUrl(root, ref, digest, chunks, expectedSize)
	}

	blobRef, err := name.NewDigest(ref)
	if err != nil {
		return nil, "", err
	}

	opts := h.remoteOptions(w, r, blobRef.Context().Name())
	l, err := remote.Layer(blobRef, opts...)
	if err != nil {
		return nil, "", err
	}

	rc, err := l.Compressed()
	if err != nil {
		return nil, "", err
	}

	size := expectedSize
	if size == 0 {
		size, err = l.Size()
		if err != nil {
			defer rc.Close()
			return nil, "", err
		}
	}
	sb := &sizeBlob{rc: rc, size: size}
	return sb, root + ref, err
}

func (h *handler) resolveUrl(w http.ResponseWriter, r *http.Request) (string, error) {
	path, root, err := splitFsURL(r.URL.Path)
	if err != nil {
		return "", err
	}

	chunks := strings.SplitN(path, "@", 2)
	if len(chunks) != 2 {
		return "", fmt.Errorf("not enough chunks: %s", path)
	}
	// 71 = len("sha256:") + 64
	if len(chunks[1]) < 71 {
		return "", fmt.Errorf("second chunk too short: %s", chunks[1])
	}

	digest := ""
	if strings.HasPrefix(chunks[1], "sha256:") {
		digest = chunks[1][:71]
	} else if strings.HasPrefix(chunks[1], "sha512:") {
		digest = chunks[1][:135]
	}

	ref := strings.Join([]string{chunks[0], digest}, "@")
	if ref == "" {
		return "", fmt.Errorf("bad ref: %s", path)
	}

	if root == "/http/" || root == "/https/" {
		u, err := url.PathUnescape(chunks[0])
		if err != nil {
			return "", err
		}

		scheme := "https://"
		if root == "/http/" {
			scheme = "http://"
		}
		return scheme + u, nil
	}

	blobRef, err := name.NewDigest(ref)
	if err != nil {
		return "", err
	}

	opts := h.remoteOptions(w, r, blobRef.Context().Name())
	l, err := remote.Blob(blobRef, "", opts...)
	if err != nil {
		return "", err
	}

	return l.Url, nil
}

func (h *handler) fetchUrl(root, ref, digest string, chunks []string, expectedSize int64) (*sizeBlob, string, error) {
	u, err := url.PathUnescape(chunks[0])
	if err != nil {
		return nil, "", err
	}

	scheme := "https://"
	if root == "/http/" {
		scheme = "http://"
	}
	u = scheme + u
	log.Printf("GET %v", u)

	resp, err := http.Get(u)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode == http.StatusOK {
		h, err := v1.NewHash(digest)
		if err != nil {
			return nil, "", err
		}
		checked, err := verify.ReadCloser(resp.Body, resp.ContentLength, h)
		if err != nil {
			return nil, "", err
		}
		size := expectedSize
		if size != 0 {
			if got := resp.ContentLength; got != -1 && got != size {
				log.Printf("GET %s unexpected size: got %d, want %d", u, got, expectedSize)
			}
		} else {
			size = resp.ContentLength
		}
		sb := &sizeBlob{rc: checked, size: size}
		return sb, root + ref, nil
	}
	resp.Body.Close()
	return nil, "", fmt.Errorf("GET %s failed: %s", u, resp.Status)
}

// parse ref out of r
// this is duplicated and desperately needs refactoring
func (h *handler) getDigest(w http.ResponseWriter, r *http.Request) (name.Digest, string, error) {
	path, root, err := splitFsURL(r.URL.Path)
	if err != nil {
		return name.Digest{}, "", err
	}

	chunks := strings.SplitN(path, "@", 2)
	if len(chunks) != 2 {
		return name.Digest{}, "", fmt.Errorf("not enough chunks: %s", path)
	}
	// 71 = len("sha256:") + 64
	if len(chunks[1]) < 71 {
		return name.Digest{}, "", fmt.Errorf("second chunk too short: %s", chunks[1])
	}

	digest := ""
	if strings.HasPrefix(chunks[1], "sha256:") {
		digest = chunks[1][:71]
	} else if strings.HasPrefix(chunks[1], "sha512:") {
		digest = chunks[1][:135]
	}

	ref := strings.Join([]string{chunks[0], digest}, "@")
	if ref == "" {
		return name.Digest{}, "", fmt.Errorf("bad ref: %s", path)
	}

	if root == "/http/" || root == "/https/" {
		fake := "example.com/foreign/layer" + "@" + digest
		dig, err := name.NewDigest(fake)
		if err != nil {
			return name.Digest{}, "", err
		}
		return dig, root + ref, nil
	}
	if root == "/cache/" {
		idx, ref, ok := strings.Cut(ref, "/")
		if !ok {
			return name.Digest{}, "", fmt.Errorf("strings.Cut(%q)", ref)
		}
		dig, err := name.NewDigest(ref)
		if err != nil {
			return name.Digest{}, "", err
		}
		return dig, idx, nil
	}

	dig, err := name.NewDigest(ref)
	if err != nil {
		return name.Digest{}, "", err
	}

	return dig, root + ref, nil
}
