package apk

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func (h *handler) remoteOptions(w http.ResponseWriter, r *http.Request, repo string) []remote.Option {
	ctx := r.Context()

	// TODO: Set timeout.
	opts := []remote.Option{}
	opts = append(opts, remote.WithContext(ctx))

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

	if _, ok := ref.(name.Digest); ok {
		if desc, ok := h.manifests[ref.Identifier()]; ok {
			return desc, nil
		}
	}

	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, err
	}
	h.manifests[desc.Digest.String()] = desc
	return desc, nil
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

	// TODO: Use sha1 for digest.
	prefix, rest, ok := strings.Cut(path, "@")
	if !ok {
		return nil, "", fmt.Errorf("missing @: %s", path)
	}

	digest, fp, ok := strings.Cut(rest, "/")
	if !ok {
		// Not a problem but no path component.
	}

	ref := prefix + "@" + digest

	if root == "/http/" || root == "/https/" {
		return h.fetchUrl(root, ref, digest, prefix, expectedSize)
	}

	// TODO
	_ = fp
	return nil, "", fmt.Errorf("todo")
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

	digest := chunks[1][:71]

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

func (h *handler) fetchUrl(root string, ref string, digest string, prefix string, expectedSize int64) (*sizeBlob, string, error) {
	u, err := url.PathUnescape(prefix)
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
		size := expectedSize
		if size != 0 {
			if got := resp.ContentLength; got != -1 && got != size {
				log.Printf("GET %s unexpected size: got %d, want %d", u, got, expectedSize)
			}
		} else {
			size = resp.ContentLength
		}
		sb := &sizeBlob{resp.Body, size}
		return sb, root + prefix, nil
	}
	resp.Body.Close()
	return nil, "", fmt.Errorf("GET %s failed: %s", u, resp.Status)
}

// parse ref out of r
// this is duplicated and desperately needs refactoring
func (h *handler) getDigest(w http.ResponseWriter, r *http.Request) (string, string, error) {
	path, root, err := splitFsURL(r.URL.Path)
	if err != nil {
		return "", "", err
	}

	// TODO: Use sha1 for digest.
	prefix, rest, ok := strings.Cut(path, "@")
	if !ok {
		// If we don't have an @, that means we need to figure out some hash for this thing.
		// That means we are probably dealing with an APKINDEX.tar.gz file.
		// TODO: HEAD it and use `etag:$HEX` as the "hash"?
		return "", "", fmt.Errorf("missing @: %s", path)
	}

	digest, fp, ok := strings.Cut(rest, "/")
	if !ok {
		// Not a problem but no path component.
	}

	ref := prefix + "@" + digest

	if root == "/http/" || root == "/https/" {
		return digest, root + ref, nil
	}

	// TODO
	_ = fp
	return "", "", fmt.Errorf("getDigest: todo")
}
