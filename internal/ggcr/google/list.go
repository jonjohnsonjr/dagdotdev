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

package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jonjohnsonjr/dagdotdev/internal/ggcr/authn"
	"github.com/jonjohnsonjr/dagdotdev/internal/ggcr/logs"
	"github.com/jonjohnsonjr/dagdotdev/internal/ggcr/name"
	"github.com/jonjohnsonjr/dagdotdev/internal/ggcr/transport"
)

// Option is a functional option for List and Walk.
// TODO: Can we somehow reuse the remote options here?
type Option func(*lister) error

type lister struct {
	auth      authn.Authenticator
	transport http.RoundTripper
	repo      name.Repository
	client    *http.Client
	ctx       context.Context
	userAgent string
}

func newLister(repo name.Repository, options ...Option) (*lister, error) {
	l := &lister{
		auth:      authn.Anonymous,
		transport: http.DefaultTransport,
		repo:      repo,
		ctx:       context.Background(),
	}

	for _, option := range options {
		if err := option(l); err != nil {
			return nil, err
		}
	}

	// Wrap with debug logging only when the Debug logger is actually enabled —
	// generating the request/response dumps is expensive otherwise.
	if logs.Enabled(logs.Debug) {
		l.transport = transport.NewLogger(l.transport)
	}
	l.transport = transport.NewRetry(l.transport)
	if l.userAgent != "" {
		l.transport = transport.NewUserAgent(l.transport, l.userAgent)
	}

	scopes := []string{repo.Scope(transport.PullScope)}
	tr, err := transport.NewWithContext(l.ctx, repo.Registry, l.auth, l.transport, scopes)
	if err != nil {
		return nil, err
	}

	l.client = &http.Client{Transport: tr}

	return l, nil
}

func (l *lister) list(repo name.Repository) (*Tags, error) {
	path := "/v2/tags/list"
	if r := repo.RepositoryStr(); r != "" {
		path = fmt.Sprintf("/v2/%s/tags/list", repo.RepositoryStr())
	}
	uri := &url.URL{
		Scheme: repo.Registry.Scheme(),
		Host:   repo.Registry.RegistryStr(),
		Path:   path,
		// ECR returns an error if n > 1000:
		// https://github.com/google/go-containerregistry/issues/681
		RawQuery: "n=1000",
	}

	tags := Tags{}

	// get responses until there is no next page
	for {
		select {
		case <-l.ctx.Done():
			return nil, l.ctx.Err()
		default:
		}

		req, err := http.NewRequest("GET", uri.String(), nil)
		if err != nil {
			return nil, err
		}
		req = req.WithContext(l.ctx)

		resp, err := l.client.Do(req)
		if err != nil {
			return nil, err
		}

		if err := transport.CheckError(resp, http.StatusOK); err != nil {
			return nil, err
		}

		parsed := Tags{}
		if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
			return nil, err
		}

		if err := resp.Body.Close(); err != nil {
			return nil, err
		}

		if len(parsed.Manifests) != 0 || len(parsed.Children) != 0 {
			// We're dealing with GCR, just return directly.
			return &parsed, nil
		}

		// This isn't GCR, just append the tags and keep paginating.
		tags.Tags = append(tags.Tags, parsed.Tags...)

		uri, err = getNextPageURL(resp)
		if err != nil {
			return nil, err
		}
		// no next page
		if uri == nil {
			break
		}
		logs.Warn.Printf("saw non-google tag listing response, falling back to pagination")
	}

	return &tags, nil
}

// getNextPageURL checks if there is a Link header in a http.Response which
// contains a link to the next page. If yes it returns the url.URL of the next
// page otherwise it returns nil.
func getNextPageURL(resp *http.Response) (*url.URL, error) {
	link := resp.Header.Get("Link")
	if link == "" {
		return nil, nil
	}

	if link[0] != '<' {
		return nil, fmt.Errorf("failed to parse link header: missing '<' in: %s", link)
	}

	end := strings.Index(link, ">")
	if end == -1 {
		return nil, fmt.Errorf("failed to parse link header: missing '>' in: %s", link)
	}
	link = link[1:end]

	linkURL, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	if resp.Request == nil || resp.Request.URL == nil {
		return nil, nil
	}
	linkURL = resp.Request.URL.ResolveReference(linkURL)
	return linkURL, nil
}

type rawManifestInfo struct {
	Size      string   `json:"imageSizeBytes"`
	MediaType string   `json:"mediaType"`
	Created   string   `json:"timeCreatedMs"`
	Uploaded  string   `json:"timeUploadedMs"`
	Tags      []string `json:"tag"`
}

// ManifestInfo is a Manifests entry is the output of List and Walk.
type ManifestInfo struct {
	Size      uint64    `json:"imageSizeBytes"`
	MediaType string    `json:"mediaType"`
	Created   time.Time `json:"timeCreatedMs"`
	Uploaded  time.Time `json:"timeUploadedMs"`
	Tags      []string  `json:"tag"`
}

func fromUnixMs(ms int64) time.Time {
	sec := ms / 1000
	ns := (ms % 1000) * 1000000
	return time.Unix(sec, ns)
}

func toUnixMs(t time.Time) string {
	return strconv.FormatInt(t.UnixNano()/1000000, 10)
}

// MarshalJSON implements json.Marshaler
func (m ManifestInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawManifestInfo{
		Size:      strconv.FormatUint(m.Size, 10),
		MediaType: m.MediaType,
		Created:   toUnixMs(m.Created),
		Uploaded:  toUnixMs(m.Uploaded),
		Tags:      m.Tags,
	})
}

// UnmarshalJSON implements json.Unmarshaler
func (m *ManifestInfo) UnmarshalJSON(data []byte) error {
	raw := rawManifestInfo{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw.Size != "" {
		size, err := strconv.ParseUint(raw.Size, 10, 64)
		if err != nil {
			return err
		}
		m.Size = size
	}

	if raw.Created != "" {
		created, err := strconv.ParseInt(raw.Created, 10, 64)
		if err != nil {
			return err
		}
		m.Created = fromUnixMs(created)
	}

	if raw.Uploaded != "" {
		uploaded, err := strconv.ParseInt(raw.Uploaded, 10, 64)
		if err != nil {
			return err
		}
		m.Uploaded = fromUnixMs(uploaded)
	}

	m.MediaType = raw.MediaType
	m.Tags = raw.Tags

	return nil
}

// Tags is the result of List and Walk.
type Tags struct {
	Children  []string                `json:"child"`
	Manifests map[string]ManifestInfo `json:"manifest"`
	Name      string                  `json:"name"`
	Tags      []string                `json:"tags"`
}

// List calls /tags/list for the given repository.
func List(repo name.Repository, options ...Option) (*Tags, error) {
	l, err := newLister(repo, options...)
	if err != nil {
		return nil, err
	}

	return l.list(repo)
}

