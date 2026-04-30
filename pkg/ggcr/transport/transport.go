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

package transport

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/authn"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/name"
)

// NewWithContext returns an http.RoundTripper that authenticates against
// `reg` for the given scopes. The handshake is:
//   1. Ping the registry to discover the auth scheme.
//   2. For anonymous/basic challenges, wrap with basicTransport.
//   3. For bearer challenges, exchange basic creds for a bearer token and
//      wrap with bearerTransport (which refreshes on 401).
func NewWithContext(ctx context.Context, reg name.Registry, auth authn.Authenticator, t http.RoundTripper, scopes []string) (http.RoundTripper, error) {
	pr, err := Ping(ctx, reg, t)
	if err != nil {
		return nil, err
	}

	// Wrap t with a useragent transport unless we already have one.
	if _, ok := t.(*userAgentTransport); !ok {
		t = NewUserAgent(t, "")
	}

	// Wrap t in a transport that selects the appropriate scheme based on the ping response.
	t = &schemeTransport{
		scheme:   pr.Scheme,
		registry: reg,
		inner:    t,
	}

	switch pr.challenge.Canonical() {
	case anonymous, basic:
		return &basicTransport{inner: t, auth: auth, target: reg.RegistryStr()}, nil
	case bearer:
		realm, ok := pr.Parameters["realm"]
		if !ok {
			return nil, fmt.Errorf("malformed www-authenticate, missing realm: %v", pr.Parameters)
		}
		bt := &bearerTransport{
			inner:    t,
			basic:    auth,
			realm:    realm,
			registry: reg,
			service:  pr.Parameters["service"],
			scopes:   scopes,
			scheme:   pr.Scheme,
		}
		if err := bt.refresh(ctx); err != nil {
			return nil, err
		}
		return bt, nil
	default:
		return nil, fmt.Errorf("unrecognized challenge: %s", pr.challenge)
	}
}
