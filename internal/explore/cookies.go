package explore

import (
	"net/http"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

type RedirectCookie struct {
	Digest string
	Url    string
}

func (h *handler) transportFromCookie(w http.ResponseWriter, r *http.Request, repo string, auth authn.Authenticator) (http.RoundTripper, error) {
	parsed, err := name.NewRepository(repo)
	if err != nil {
		return nil, err
	}
	scopes := []string{parsed.Scope(transport.PullScope)}
	reg := parsed.Registry

	t := remote.DefaultTransport
	t = transport.NewRetry(t)
	t = transport.NewUserAgent(t, h.userAgent)
	if r.URL.Query().Get("trace") != "" {
		t = transport.NewTracer(t)
	}

	h.Lock()
	pr, ok := h.pings[reg.String()]
	h.Unlock()
	if !ok {
		pr, err = transport.Ping(r.Context(), reg, t)
		if err != nil {
			return nil, err
		}
		h.Lock()
		h.pings[reg.String()] = pr
		h.Unlock()
	}

	h.Lock()
	tok, ok := h.tokens[parsed.String()]
	h.Unlock()
	if ok && !tok.Expires.Before(time.Now().Add(30*time.Second)) {
		// If this won't expire within 30 seconds, reuse it.
		return transport.OldBearer(pr, tok.TokenResponse, reg, auth, t, scopes)
	}

	// We don't have a cached token or it's expired (or about to), so get a new one.
	rt, tr, err := transport.NewBearer(r.Context(), pr, reg, auth, t, scopes)
	if err != nil {
		return nil, err
	}

	// Probably no auth needed.
	if tr == nil {
		return rt, nil
	}

	// Clear this to make cache smaller (sometimes this duplicates Token).
	tr.AccessToken = ""

	if tr.ExpiresIn == 0 {
		tr.ExpiresIn = 60
	}
	exp := time.Now().Add(time.Second * time.Duration(tr.ExpiresIn))
	tok = token{
		TokenResponse: tr,
		Expires:       exp,
	}

	h.Lock()
	h.tokens[parsed.String()] = tok
	h.Unlock()

	return rt, nil
}
