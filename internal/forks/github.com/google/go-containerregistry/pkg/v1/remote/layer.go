// Copyright 2019 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package remote

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-containerregistry/internal/redact"
	"github.com/google/go-containerregistry/internal/verify"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// remoteImagelayer implements partial.CompressedLayer
type remoteLayer struct {
	fetcher
	digest v1.Hash
	size   int64
}

// Compressed implements partial.CompressedLayer
func (rl *remoteLayer) Compressed() (io.ReadCloser, error) {
	// We don't want to log binary layers -- this can break terminals.
	ctx := redact.NewContext(rl.context, "omitting binary blobs from logs")
	rc, size, err := rl.fetchBlob(ctx, verify.SizeUnknown, rl.digest)
	rl.size = size
	return rc, err
}

// Compressed implements partial.CompressedLayer
func (rl *remoteLayer) Size() (int64, error) {
	if rl.size > 0 {
		return rl.size, nil
	}
	var (
		resp *http.Response
		err  error
	)
	if strings.HasPrefix(rl.fetcher.Ref.Name(), "public.ecr.aws/") {
		// HEAD is broken for some reason T_T.
		resp, err = rl.getBlob(rl.digest)
		if err != nil {
			return -1, err
		}
	} else {
		resp, err = rl.headBlob(rl.digest)
		if err != nil {
			return -1, err
		}
	}
	defer resp.Body.Close()
	return resp.ContentLength, nil
}

// Digest implements partial.CompressedLayer
func (rl *remoteLayer) Digest() (v1.Hash, error) {
	return rl.digest, nil
}

// MediaType implements v1.Layer
func (rl *remoteLayer) MediaType() (types.MediaType, error) {
	return types.DockerLayer, nil
}

// See partial.Exists.
func (rl *remoteLayer) Exists() (bool, error) {
	return rl.blobExists(rl.digest)
}

// Layer reads the given blob reference from a registry as a Layer. A blob
// reference here is just a punned name.Digest where the digest portion is the
// digest of the blob to be read and the repository portion is the repo where
// that blob lives.
func Layer(ref name.Digest, options ...Option) (v1.Layer, error) {
	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return nil, err
	}
	f, err := makeFetcher(ref, o)
	if err != nil {
		return nil, err
	}
	h, err := v1.NewHash(ref.Identifier())
	if err != nil {
		return nil, err
	}
	l, err := partial.CompressedToLayer(&remoteLayer{
		fetcher: *f,
		digest:  h,
		size:    o.size,
	})
	if err != nil {
		return nil, err
	}
	return &MountableLayer{
		Layer:     l,
		Reference: ref,
	}, nil
}

// BlobSeeker implements io.ReaderAt.
type BlobSeeker struct {
	rl   *remoteLayer
	size int64
	done func(*BlobSeeker) error

	Body   io.ReadCloser
	Status int

	Url string

	ref       name.Digest
	cachedUrl string
	options   []Option
}

func LazyBlob(ref name.Digest, cachedUrl string, done func(*BlobSeeker) error, options ...Option) *BlobSeeker {
	return &BlobSeeker{
		ref:       ref,
		cachedUrl: cachedUrl,
		options:   options,
		done:      done,
	}
}

func (bs *BlobSeeker) init(start, end int64) error {
	if end == 0 {
		end = 1
	}
	o, err := makeOptions(bs.ref.Context(), bs.options...)
	if err != nil {
		return err
	}
	f, err := makeFetcher(bs.ref, o)
	if err != nil {
		return err
	}
	h, err := v1.NewHash(bs.ref.Identifier())
	if err != nil {
		return err
	}
	rl := &remoteLayer{
		fetcher: *f,
		digest:  h,
		size:    o.size,
	}
	if o.size == 0 {
		logs.Debug.Printf("should never call this")
		if bs.cachedUrl != "" {
			resp, err := f.Client.Head(bs.cachedUrl)
			if err != nil {
				return err
			}
			o.size = resp.ContentLength
		} else {
			o.size, err = rl.Size()
			if err != nil {
				return err
			}
		}
	}

	rangePrefix := "bytes="
	rangeSuffix := fmt.Sprintf("%d-%d", start, end)

	urlStr := bs.cachedUrl
	var res *http.Response
	if bs.cachedUrl == "" {
		ctx := redact.NewContext(o.context, "omitting binary blobs from logs")

		u := f.url("blobs", h.String())
		urlStr = u.String()

		for {
			logs.Debug.Printf("urlStr: %s", urlStr)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
			if err != nil {
				return err
			}
			if !strings.Contains(urlStr, "gcr.io") || strings.Contains(urlStr, "/artifacts-downloads/") {
				req.Header.Set("Range", rangePrefix+rangeSuffix)
				logs.Debug.Printf("Range: %s%s", rangePrefix, rangeSuffix)
			}

			tr := f.Client.Transport
			res, err = tr.RoundTrip(req)
			if err != nil {
				return err
			}

			if redir := res.Header.Get("Location"); redir != "" && res.StatusCode/100 == 3 {
				res.Body.Close()

				u, err := url.Parse(redir)
				if err != nil {
					return err
				}
				urlStr = req.URL.ResolveReference(u).String()
				continue
			}

			// Attempt to recover from distribution nonsense range headers.
			if res.StatusCode >= 400 {
				terr := transport.CheckError(res)
				if rangePrefix != "" && strings.Contains(terr.Error(), `^[0-9]+\\-[0-9]+$`) {
					logs.Debug.Printf("Retrying with no bytes= prefix")
					rangePrefix = ""
					continue
				}
				res.Body.Close()
				return terr
			}

			break
		}
		if res.StatusCode == 200 {
			logs.Debug.Printf("does not look like it supports range requests")
		}

		logs.Debug.Printf("got past redir")

		if res.StatusCode >= 400 {
			return transport.CheckError(res)
		}
	} else {
		logs.Debug.Printf("using cached url: %s", bs.cachedUrl)
	}

	logs.Debug.Printf("setting urlStr: %s", urlStr)

	bs.rl = rl
	bs.size = o.size
	bs.Url = urlStr

	if res != nil {
		bs.Status = res.StatusCode
		bs.Body = res.Body
	}

	if bs.done != nil {
		return bs.done(bs)
	}
	return nil
}

// Blob returns a seekable blob.
func Blob(ref name.Digest, cachedUrl string, options ...Option) (*BlobSeeker, error) {
	bs := LazyBlob(ref, cachedUrl, nil, options...)
	return bs, bs.init(0, 1)
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
	if b.rl == nil {
		if err := b.init(off, off+int64(len(p))+1); err != nil {
			return 0, err
		}
	}
	logs.Debug.Printf("ReadAt")
	// TODO: configurable timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx = redact.NewContext(ctx, "omitting binary blobs from logs")
	req, err := http.NewRequestWithContext(ctx, "GET", b.Url, nil)
	if err != nil {
		return 0, err
	}
	rangeVal := fmt.Sprintf("bytes=%d-%d", off, off+int64(len(p))-1)
	req.Header.Set("Range", rangeVal)
	logs.Debug.Printf("Fetching %s (%d at %d) of %s ...\n", rangeVal, len(p), off, b.Url)
	res, err := b.rl.Client.Transport.RoundTrip(req) // NOT DefaultClient; don't want redirects
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
	if b.rl == nil {
		if err := b.init(off, end-1); err != nil {
			return nil, err
		}
	}
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
	ctx = redact.NewContext(ctx, "omitting binary blobs from logs")
	req, err := http.NewRequestWithContext(ctx, "GET", b.Url, nil)
	if err != nil {
		return nil, err
	}
	rangeVal := fmt.Sprintf("bytes=%d-%d", off, end-1)
	req.Header.Set("Range", rangeVal)
	logs.Debug.Printf("Fetching %s at %s ...\n", rangeVal, b.Url)
	res, err := b.rl.Client.Transport.RoundTrip(req) // NOT DefaultClient; don't want redirects
	if err != nil {
		logs.Debug.Printf("range read of %s: %v", b.Url, err)
		return nil, err
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
