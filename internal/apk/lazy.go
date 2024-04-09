package apk

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
)

type BlobSeeker struct {
	size int64

	keychain authn.Keychain

	Body   io.ReadCloser
	Status int

	Url string

	cachedUrl string
}

func LazyBlob(cachedUrl string, size int64, keychain authn.Keychain) *BlobSeeker {
	return &BlobSeeker{
		Url:       cachedUrl,
		cachedUrl: cachedUrl,
		size:      size,
		keychain:  keychain,
	}
}

func (b *BlobSeeker) Size() int64 {
	return b.size
}

func (b *BlobSeeker) Read(p []byte) (n int, err error) {
	// logs.Debug.Printf("Read of %d", len(p))
	return b.Body.Read(p)
}

func (b *BlobSeeker) Close() error {
	return b.Body.Close()
}

func (b *BlobSeeker) ReadAt(p []byte, off int64) (n int, err error) {
	logs.Debug.Printf("ReadAt")
	// TODO: configurable timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", b.Url, nil)
	if err != nil {
		return 0, err
	}
	if b.keychain != nil {
		ref := name.MustParseReference("gcr.io/example")
		auth, err := b.keychain.Resolve(ref.Context().Registry)
		if err != nil {
			return 0, fmt.Errorf("keychain resolve: %w", err)
		}
		basic, err := auth.Authorization()
		if err != nil {
			return 0, fmt.Errorf("keychain auth: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+basic.Password)
	}
	rangeVal := fmt.Sprintf("bytes=%d-%d", off, off+int64(len(p))-1)
	req.Header.Set("Range", rangeVal)
	logs.Debug.Printf("Fetching %s (%d at %d) of %s ...\n", rangeVal, len(p), off, b.Url)
	res, err := http.DefaultTransport.RoundTrip(req) // NOT DefaultClient; don't want redirects
	if err != nil {
		logs.Debug.Printf("range read of %s: %v", b.Url, err)
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusPartialContent {
		logs.Debug.Printf("range read of %s: %v", b.Url, res.Status)
		if redir := res.Header.Get("Location"); redir != "" && res.StatusCode/100 == 3 {
			res.Body.Close()

			u, err := url.Parse(redir)
			if err != nil {
				return -1, err
			}
			b.Url = req.URL.ResolveReference(u).String()
			b.cachedUrl = b.Url
			return b.ReadAt(p, off)
		}
		return 0, err
	}
	return io.ReadFull(res.Body, p)
}

func (b *BlobSeeker) Reader(ctx context.Context, off int64, end int64) (io.ReadCloser, error) {
	if b.Body != nil {
		if b.Status == 200 {
			logs.Debug.Printf("Didn't support range requests")
			logs.Debug.Printf("Discarding %d bytes", off)
			// Didn't support range requests.
			if _, err := io.CopyN(io.Discard, b.Body, off); err != nil {
				return nil, err
			}
		}
		ret := b.Body
		b.Body = nil
		return ret, nil
	}

	if end == -1 {
		end = b.size
	}
	req, err := http.NewRequestWithContext(ctx, "GET", b.Url, nil)
	if err != nil {
		return nil, err
	}
	if b.keychain != nil {
		ref := name.MustParseReference("gcr.io/example")
		auth, err := b.keychain.Resolve(ref.Context().Registry)
		if err != nil {
			return nil, fmt.Errorf("keychain resolve: %w", err)
		}
		basic, err := auth.Authorization()
		if err != nil {
			return nil, fmt.Errorf("keychain auth: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+basic.Password)
	}
	rangeVal := fmt.Sprintf("bytes=%d-%d", off, end-1)
	req.Header.Set("Range", rangeVal)
	logs.Debug.Printf("Fetching %s at %s ...\n", rangeVal, b.Url)
	res, err := http.DefaultTransport.RoundTrip(req) // NOT DefaultClient; don't want redirects
	if err != nil {
		logs.Debug.Printf("range read of %s: %v", b.Url, err)
		return nil, err
	}
	if res.StatusCode == 200 {
		logs.Debug.Printf("Didn't support range requests")
		logs.Debug.Printf("Discarding %d bytes", off)
		// Didn't support range requests.
		if _, err := io.CopyN(io.Discard, res.Body, off); err != nil {
			return nil, err
		}
		return &blobReader{
			bs:   b,
			body: res.Body,
		}, nil
	}
	if res.StatusCode != http.StatusPartialContent {
		logs.Debug.Printf("range read of %s: %v", b.Url, res.Status)
		if redir := res.Header.Get("Location"); redir != "" && res.StatusCode/100 == 3 {
			res.Body.Close()

			u, err := url.Parse(redir)
			if err != nil {
				return nil, err
			}
			b.Url = req.URL.ResolveReference(u).String()
			b.cachedUrl = b.Url
			return b.Reader(ctx, off, end)
		}
		return nil, err
	}

	return &blobReader{
		bs:   b,
		body: res.Body,
	}, nil
}

type blobReader struct {
	bs   *BlobSeeker
	body io.ReadCloser
}

func (b *blobReader) Read(p []byte) (n int, err error) {
	// logs.Debug.Printf("Read of %d", len(p))
	return b.body.Read(p)
}

func (b *blobReader) Close() error {
	return b.body.Close()
}
