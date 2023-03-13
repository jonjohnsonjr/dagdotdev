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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

type Catalogs struct {
	Repos []string `json:"repositories"`
	Next  string   `json:"next,omitempty"`
}

// CatalogPage calls /_catalog, returning the list of repositories on the registry.
func CatalogPage(target name.Registry, next string, options ...Option) (*Catalogs, error) {
	o, err := makeOptions(target, options...)
	if err != nil {
		return nil, err
	}

	scopes := []string{target.Scope(transport.PullScope)}
	tr, err := transport.NewWithContext(o.context, target, o.auth, o.transport, scopes)
	if err != nil {
		return nil, err
	}

	uri := url.URL{
		Scheme: target.Scheme(),
		Host:   target.RegistryStr(),
		Path:   "/v2/_catalog",
	}
	if o.pageSize > 0 {
		uri.RawQuery = fmt.Sprintf("n=%d", o.pageSize)
	}
	if next == "" {
		next = uri.String()
	}

	client := http.Client{Transport: tr}

	return catalogPage(o.context, client, next)
}

func catalogPage(ctx context.Context, client http.Client, uri string) (*Catalogs, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		return nil, err
	}

	parsed := Catalogs{}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}

	if err := resp.Body.Close(); err != nil {
		return nil, err
	}

	next, err := getNextPageURL(resp)
	if err != nil {
		return nil, err
	}

	if next != nil {
		parsed.Next = next.String()
	}

	return &parsed, nil
}

// Catalog calls /_catalog, returning the list of repositories on the registry.
func Catalog(ctx context.Context, target name.Registry, options ...Option) ([]string, error) {
	o, err := makeOptions(target, options...)
	if err != nil {
		return nil, err
	}

	scopes := []string{target.Scope(transport.PullScope)}
	tr, err := transport.NewWithContext(o.context, target, o.auth, o.transport, scopes)
	if err != nil {
		return nil, err
	}

	uri := &url.URL{
		Scheme: target.Scheme(),
		Host:   target.RegistryStr(),
		Path:   "/v2/_catalog",
	}

	if o.pageSize > 0 {
		uri.RawQuery = fmt.Sprintf("n=%d", o.pageSize)
	}

	client := http.Client{Transport: tr}

	// WithContext overrides the ctx passed directly.
	if o.context != context.Background() {
		ctx = o.context
	}

	parsed := &Catalogs{
		Next: uri.String(),
	}
	repoList := []string{}

	// get responses until there is no next page
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		parsed, err = catalogPage(o.context, client, parsed.Next)
		if err != nil {
			return nil, err
		}

		repoList = append(repoList, parsed.Repos...)

		// no next page
		if parsed.Next == "" {
			break
		}
	}
	return repoList, nil
}
