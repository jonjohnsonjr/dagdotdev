package apk

import (
	"context"
	"net/http"
)

// Authenticator stamps an outbound HTTP request with whatever auth scheme the
// caller wants. apk.WithAuth lets the binary plug in an implementation.
//
// We used to ship a Chainguard-specific implementation here that exchanged a
// GCP id-token for a cgr.dev access token; that lives outside this repo now.
type Authenticator interface {
	AddAuth(ctx context.Context, req *http.Request) error
}
