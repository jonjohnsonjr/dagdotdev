package apk

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// Fetch blob from registry or URL.
func (h *handler) fetchArg(w http.ResponseWriter, r *http.Request, arg string) (*sizeBlob, string, error) {
	ref := ""

	var (
		err     error
		p, root string
	)
	if r.URL.Path == "/" {
	} else {
		p, root, err = splitFsURL(r.URL.Path)
		if err != nil {
			return nil, "", err
		}

		// TODO: Use sha1 for digest.
		prefix, rest, ok := strings.Cut(p, "@")
		if !ok {
			return nil, "", fmt.Errorf("missing @ (this should not happen): %q", p)
		}

		// We want to get the part after @ but before the filepath.
		digest, _, ok := strings.Cut(rest, "/")
		if !ok {
			ref = prefix + "@" + rest
		} else {
			ref = prefix + "@" + digest
		}
	}

	rc, err := os.Open(arg)
	if err != nil {
		return nil, "", err
	}

	info, err := rc.Stat()
	if err != nil {
		return nil, "", err
	}

	blob := &sizeBlob{rc, info.Size()}

	return blob, root + ref, err
}

// Fetch blob from registry or URL.
func (h *handler) fetchBlob(w http.ResponseWriter, r *http.Request) (*sizeBlob, string, error) {
	p, root, err := splitFsURL(r.URL.Path)
	if err != nil {
		return nil, "", err
	}

	ref := ""

	// TODO: Use sha1 for digest.
	prefix, rest, ok := strings.Cut(p, "@")
	if !ok {
		return nil, "", fmt.Errorf("missing @ (this should not happen): %q", p)
	}

	// We want to get the part after @ but before the filepath.
	digest, _, ok := strings.Cut(rest, "/")
	if !ok {
		ref = prefix + "@" + rest
	} else {
		ref = prefix + "@" + digest
	}

	u, err := getUpstreamURL(r)
	if err != nil {
		return nil, "", err
	}

	blob, err := h.fetchUrl(u)
	if err != nil {
		return nil, "", fmt.Errorf("fetchUrl: %w", err)
	}

	return blob, root + ref, err
}

// TODO: We need a LazyBlob version of this so we can use the cached index.
// TODO: In-memory cache that respects cache headers?
func (h *handler) fetchUrl(u string) (*sizeBlob, error) {
	log.Printf("GET %v", u)

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if err := h.addAuth(req); err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s failed: %s", u, resp.Status)
	}

	size := resp.ContentLength
	sb := &sizeBlob{resp.Body, size}

	return sb, nil
}

func (h *handler) headUrl(u string) (string, error) {
	log.Printf("HEAD %v", u)

	req, err := http.NewRequest(http.MethodHead, u, nil)
	if err != nil {
		return "", err
	}
	if err := h.addAuth(req); err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HEAD %s failed: %s", u, resp.Status)
	}

	// TODO: What to do if etag does not exist?
	return resp.Header.Get("Etag"), nil
}
