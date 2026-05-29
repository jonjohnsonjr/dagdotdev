// Copyright 2018 Google LLC All Rights Reserved.
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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/internal/redact"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/internal/verify"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/name"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/transport"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/types"
	v1 "github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/v1"
)

var (
	acceptableImageMediaTypes = []types.MediaType{
		types.DockerManifestSchema2,
		types.OCIManifestSchema1,
	}
	acceptableIndexMediaTypes = []types.MediaType{
		types.DockerManifestList,
		types.OCIImageIndex,
	}
)

// Descriptor carries the manifest bytes plus the v1.Descriptor metadata
// returned for a registry artifact.
type Descriptor struct {
	v1.Descriptor
	Manifest []byte
}

// Get returns a remote.Descriptor for the given reference. The response from
// the registry is left un-interpreted, for the most part. This is useful for
// querying what kind of artifact a reference represents.
//
// See Head if you don't need the response body.
func Get(ref name.Reference, options ...Option) (*Descriptor, error) {
	acceptable := []types.MediaType{
		// Just to look at them.
		types.DockerManifestSchema1,
		types.DockerManifestSchema1Signed,
	}
	acceptable = append(acceptable, acceptableImageMediaTypes...)
	acceptable = append(acceptable, acceptableIndexMediaTypes...)
	return get(ref, acceptable, options...)
}

// Head returns a v1.Descriptor for the given reference by issuing a HEAD
// request.
//
// Note that the server response will not have a body, so any errors encountered
// should be retried with Get to get more details.
func Head(ref name.Reference, options ...Option) (*v1.Descriptor, error) {
	acceptable := []types.MediaType{
		// Just to look at them.
		types.DockerManifestSchema1,
		types.DockerManifestSchema1Signed,
	}
	acceptable = append(acceptable, acceptableImageMediaTypes...)
	acceptable = append(acceptable, acceptableIndexMediaTypes...)

	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return nil, err
	}

	f, err := makeFetcher(ref, o)
	if err != nil {
		return nil, err
	}

	return f.headManifest(ref, acceptable)
}

// Handle options and fetch the manifest with the acceptable MediaTypes in the
// Accept header.
func get(ref name.Reference, acceptable []types.MediaType, options ...Option) (*Descriptor, error) {
	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return nil, err
	}
	f, err := makeFetcher(ref, o)
	if err != nil {
		return nil, err
	}
	b, desc, err := f.fetchManifest(ref, acceptable)
	if err != nil {
		return nil, err
	}
	return &Descriptor{
		Manifest:   b,
		Descriptor: *desc,
	}, nil
}

// fetcher implements methods for reading from a registry.
type fetcher struct {
	Ref     name.Reference
	Client  *http.Client
	options *options
	context context.Context
}

func makeFetcher(ref name.Reference, o *options) (*fetcher, error) {
	tr, err := transport.NewWithContext(o.context, ref.Context().Registry, o.auth, o.transport, []string{ref.Scope(transport.PullScope)})
	if err != nil {
		return nil, err
	}
	return &fetcher{
		Ref:     ref,
		Client:  &http.Client{Transport: tr},
		context: o.context,
		options: o,
	}, nil
}

// url returns a url.Url for the specified path in the context of this remote image reference.
func (f *fetcher) url(resource, identifier string) url.URL {
	return url.URL{
		Scheme: f.Ref.Context().Registry.Scheme(),
		Host:   f.Ref.Context().RegistryStr(),
		Path:   fmt.Sprintf("/v2/%s/%s/%s", f.Ref.Context().RepositoryStr(), resource, identifier),
	}
}

// https://github.com/opencontainers/distribution-spec/blob/main/spec.md#referrers-tag-schema
func fallbackTag(d name.Digest) name.Tag {
	return d.Context().Tag(strings.Replace(d.DigestStr(), ":", "-", 1))
}

func (f *fetcher) fetchReferrers(ctx context.Context, d name.Digest) (*Descriptor, error) {
	// Check the Referrers API endpoint first.
	u := f.url("referrers", d.DigestStr())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", string(types.OCIImageIndex))

	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}

	if got, want := resp.ContentLength, f.options.maxSize; got > want {
		return nil, fmt.Errorf("too big: %d > %d", got, want)
	}
	defer resp.Body.Close()

	if err := transport.CheckError(resp, http.StatusOK, http.StatusNotFound, http.StatusBadRequest); err != nil {
		return nil, err
	}

	var b []byte
	if resp.StatusCode == http.StatusOK && resp.Header.Get("docker-distribution-api-version") != "" {
		b, err = io.ReadAll(io.LimitReader(resp.Body, f.options.maxSize))
		if err != nil {
			return nil, err
		}
	} else {
		// The registry doesn't support the Referrers API endpoint; use the fallback tag scheme.
		b, _, err = f.fetchManifest(fallbackTag(d), []types.MediaType{types.OCIImageIndex})
		var terr *transport.Error
		if ok := errors.As(err, &terr); ok && terr.StatusCode == http.StatusNotFound {
			// No attachments yet — return an empty index manifest.
			return emptyReferrers(), nil
		} else if err != nil {
			return nil, err
		}
	}

	h, sz, err := v1.SHA256(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return &Descriptor{
		Manifest: b,
		Descriptor: v1.Descriptor{
			Digest:    h,
			MediaType: types.OCIImageIndex,
			Size:      sz,
		},
	}, nil
}

// emptyOCIIndex is the canonical empty OCI image index manifest, used when no
// referrers exist for a subject yet.
var emptyOCIIndex = []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)

func emptyReferrers() *Descriptor {
	h, sz, _ := v1.SHA256(bytes.NewReader(emptyOCIIndex))
	return &Descriptor{
		Manifest: emptyOCIIndex,
		Descriptor: v1.Descriptor{
			Digest:    h,
			MediaType: types.OCIImageIndex,
			Size:      sz,
		},
	}
}

func (f *fetcher) fetchManifest(ref name.Reference, acceptable []types.MediaType) ([]byte, *v1.Descriptor, error) {
	u := f.url("manifests", ref.Identifier())
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	accept := []string{}
	for _, mt := range acceptable {
		accept = append(accept, string(mt))
	}
	req.Header.Set("Accept", strings.Join(accept, ","))

	resp, err := f.Client.Do(req.WithContext(f.context))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		return nil, nil, err
	}

	lr := io.LimitedReader{R: resp.Body, N: f.options.maxSize}
	manifest, err := io.ReadAll(&lr)
	if err != nil {
		return nil, nil, err
	}
	if int64(len(manifest)) > f.options.maxSize {
		return nil, nil, fmt.Errorf("manifest is bigger than %d", f.options.maxSize)
	}

	mediaType := types.MediaType(resp.Header.Get("Content-Type"))
	contentDigest, contentDigestErr := v1.NewHash(resp.Header.Get("Docker-Content-Digest"))

	// When pulling by digest, use the same algorithm as the requested digest so
	// the comparison succeeds for non-sha256 algorithms (e.g. sha512).
	// When pulling by tag, use the algorithm from the Docker-Content-Digest
	// header so the reported digest matches what the registry uses.
	// Fall back to sha256 if neither applies.
	algorithm := "sha256"
	if dgst, ok := ref.(name.Digest); ok {
		if h, err := v1.NewHash(dgst.DigestStr()); err == nil {
			algorithm = h.Algorithm
		}
	} else if contentDigestErr == nil {
		algorithm = contentDigest.Algorithm
	}
	digest, size, err := v1.HashWith(algorithm, bytes.NewReader(manifest))
	if err != nil {
		return nil, nil, err
	}

	if contentDigestErr == nil && mediaType == types.DockerManifestSchema1Signed {
		// If we can parse the digest from the header, and it's a signed schema 1
		// manifest, let's use that for the digest to appease older registries.
		digest = contentDigest
	}

	// Validate the digest matches what we asked for, if pulling by digest.
	if dgst, ok := ref.(name.Digest); ok {
		if digest.String() != dgst.DigestStr() {
			return nil, nil, fmt.Errorf("manifest digest: %q does not match requested digest: %q for %q", digest, dgst.DigestStr(), f.Ref)
		}
	}

	var artifactType string
	mf, _ := v1.ParseManifest(bytes.NewReader(manifest))
	// Failing to parse as a manifest should just be ignored.
	// The manifest might not be valid, and that's okay.
	if mf != nil && !mf.Config.MediaType.IsConfig() {
		artifactType = string(mf.Config.MediaType)
	}

	// Do nothing for tags; I give up.
	//
	// We'd like to validate that the "Docker-Content-Digest" header matches what is returned by the registry,
	// but so many registries implement this incorrectly that it's not worth checking.
	//
	// For reference:
	// https://github.com/GoogleContainerTools/kaniko/issues/298

	// Return all this info since we have to calculate it anyway.
	desc := v1.Descriptor{
		Digest:       digest,
		Size:         size,
		MediaType:    mediaType,
		ArtifactType: artifactType,
	}

	return manifest, &desc, nil
}

func (f *fetcher) headManifest(ref name.Reference, acceptable []types.MediaType) (*v1.Descriptor, error) {
	u := f.url("manifests", ref.Identifier())
	req, err := http.NewRequest(http.MethodHead, u.String(), nil)
	if err != nil {
		return nil, err
	}
	accept := []string{}
	for _, mt := range acceptable {
		accept = append(accept, string(mt))
	}
	req.Header.Set("Accept", strings.Join(accept, ","))

	resp, err := f.Client.Do(req.WithContext(f.context))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		return nil, err
	}

	mth := resp.Header.Get("Content-Type")
	if mth == "" {
		return nil, fmt.Errorf("HEAD %s: response did not include Content-Type header", u.String())
	}
	mediaType := types.MediaType(mth)

	size := resp.ContentLength
	if size == -1 {
		return nil, fmt.Errorf("GET %s: response did not include Content-Length header", u.String())
	}

	dh := resp.Header.Get("Docker-Content-Digest")
	if dh == "" {
		return nil, fmt.Errorf("HEAD %s: response did not include Docker-Content-Digest header", u.String())
	}
	digest, err := v1.NewHash(dh)
	if err != nil {
		return nil, err
	}

	// Validate the digest matches what we asked for, if pulling by digest.
	if dgst, ok := ref.(name.Digest); ok {
		if digest.String() != dgst.DigestStr() {
			return nil, fmt.Errorf("manifest digest: %q does not match requested digest: %q for %q", digest, dgst.DigestStr(), f.Ref)
		}
	}

	// Return all this info since we have to calculate it anyway.
	return &v1.Descriptor{
		Digest:    digest,
		Size:      size,
		MediaType: mediaType,
	}, nil
}

func (f *fetcher) fetchBlob(ctx context.Context, size int64, h v1.Hash) (io.ReadCloser, int64, error) {
	u := f.url("blobs", h.String())
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, -1, err
	}

	resp, err := f.Client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, -1, redact.Error(err)
	}

	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		resp.Body.Close()
		return nil, -1, err
	}

	// Do whatever we can.
	// If we have an expected size and Content-Length doesn't match, return an error.
	// If we don't have an expected size and we do have a Content-Length, use Content-Length.
	if hsize := resp.ContentLength; hsize != -1 {
		if size == verify.SizeUnknown {
			size = hsize
		} else if hsize != size {
			return nil, -1, fmt.Errorf("GET %s: Content-Length header %d does not match expected size %d", u.String(), hsize, size)
		}
	}

	rc, err := verify.ReadCloser(resp.Body, size, h)
	return rc, size, err
}

func (f *fetcher) getBlob(h v1.Hash) (*http.Response, error) {
	u := f.url("blobs", h.String())
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.Client.Do(req.WithContext(f.context))
	if err != nil {
		return nil, err
	}

	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		resp.Body.Close()
		return nil, err
	}

	return resp, nil
}

func (f *fetcher) headBlob(h v1.Hash) (*http.Response, error) {
	u := f.url("blobs", h.String())
	req, err := http.NewRequest(http.MethodHead, u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.Client.Do(req.WithContext(f.context))
	if err != nil {
		return nil, redact.Error(err)
	}

	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		resp.Body.Close()
		return nil, err
	}

	return resp, nil
}
