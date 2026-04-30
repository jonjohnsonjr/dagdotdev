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
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/jonjohnsonjr/dagdotdev/internal/ggcr/authn"
	"github.com/jonjohnsonjr/dagdotdev/internal/ggcr/internal/retry"
	"github.com/jonjohnsonjr/dagdotdev/internal/ggcr/logs"
	"github.com/jonjohnsonjr/dagdotdev/internal/ggcr/transport"
)

// Option is a functional option for remote operations.
type Option func(*options) error

type options struct {
	auth      authn.Authenticator
	keychain  authn.Keychain
	transport http.RoundTripper
	context   context.Context
	pageSize  int
	maxSize   int64

	// Optimization in case we know the size already.
	size int64

	// Avoid breaking api because I'm lazy.
	next string
}

var defaultRetryPredicate retry.Predicate = func(err error) bool {
	// Various failure modes here, as we're often reading from and writing to
	// the network.
	if retry.IsTemporary(err) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		logs.Warn.Printf("retrying %v", err)
		return true
	}
	return false
}

var retryableStatusCodes = []int{
	http.StatusRequestTimeout,
	http.StatusInternalServerError,
	http.StatusBadGateway,
	http.StatusServiceUnavailable,
	http.StatusGatewayTimeout,
}

const (
	// ECR returns an error if n > 1000:
	// https://github.com/google/go-containerregistry/issues/1091
	defaultPageSize = 1000
)

// DefaultTransport is based on http.DefaultTransport with modifications
// documented inline below.
var DefaultTransport http.RoundTripper = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ReadBufferSize:        1 << 16,
	WriteBufferSize:       1 << 16,
	TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper), // Disable HTTP/2
}

func makeOptions(target authn.Resource, opts ...Option) (*options, error) {
	o := &options{
		transport: DefaultTransport,
		context:   context.Background(),
		pageSize:  defaultPageSize,
		maxSize:   math.MaxInt64,
	}

	for _, option := range opts {
		if err := option(o); err != nil {
			return nil, err
		}
	}

	switch {
	case o.auth != nil && o.keychain != nil:
		// It is a better experience to explicitly tell a caller their auth is misconfigured
		// than potentially fail silently when the correct auth is overridden by option misuse.
		return nil, errors.New("provide an option for either authn.Authenticator or authn.Keychain, not both")
	case o.keychain != nil:
		auth, err := o.keychain.Resolve(target)
		if err != nil {
			return nil, err
		}
		o.auth = auth
	case o.auth == nil:
		o.auth = authn.Anonymous
	}

	// Wrap with debug logging only when the Debug logger is actually enabled —
	// generating the request/response dumps is expensive otherwise.
	if logs.Enabled(logs.Debug) {
		o.transport = transport.NewLogger(o.transport)
	}
	o.transport = transport.NewRetry(o.transport, transport.WithRetryPredicate(defaultRetryPredicate), transport.WithRetryStatusCodes(retryableStatusCodes...))

	return o, nil
}

// WithTransport overrides the default http.RoundTripper used for remote
// operations. The default is DefaultTransport.
func WithTransport(t http.RoundTripper) Option {
	return func(o *options) error {
		o.transport = t
		return nil
	}
}

// WithAuth is a functional option for overriding the default authenticator
// for remote operations.
// It is an error to use both WithAuth and WithAuthFromKeychain in the same Option set.
//
// The default authenticator is authn.Anonymous.
func WithAuth(auth authn.Authenticator) Option {
	return func(o *options) error {
		o.auth = auth
		o.keychain = nil
		return nil
	}
}

// WithAuthFromKeychain is a functional option for overriding the default
// authenticator for remote operations, using an authn.Keychain to find
// credentials.
// It is an error to use both WithAuth and WithAuthFromKeychain in the same Option set.
//
// The default authenticator is authn.Anonymous.
func WithAuthFromKeychain(keys authn.Keychain) Option {
	return func(o *options) error {
		o.keychain = keys
		o.auth = nil
		return nil
	}
}

// WithContext is a functional option for setting the context in http requests
// performed by a given function. Note that this context is used for _all_
// http requests, not just the initial volley. E.g., for remote.Image, the
// context will be set on http requests generated by subsequent calls to
// RawConfigFile() and even methods on layers returned by Layers().
//
// The default context is context.Background().
func WithContext(ctx context.Context) Option {
	return func(o *options) error {
		o.context = ctx
		return nil
	}
}

// WithPageSize sets the given size as the value of parameter 'n' in the request.
//
// To omit the `n` parameter entirely, use WithPageSize(0).
// The default value is 1000.
func WithPageSize(size int) Option {
	return func(o *options) error {
		o.pageSize = size
		return nil
	}
}

func WithMaxSize(size int64) Option {
	return func(o *options) error {
		o.maxSize = size
		return nil
	}
}

func WithSize(size int64) Option {
	return func(o *options) error {
		o.size = size
		return nil
	}
}

func WithNext(next string) Option {
	return func(o *options) error {
		o.next = next
		return nil
	}
}
