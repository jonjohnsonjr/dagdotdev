package explore

import (
	"errors"
	"io"
	"net/http"
	"syscall"
	"time"

	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/authn"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/logs"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/name"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/remote"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/retry"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/transport"
)

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
	} else if logs.Enabled(logs.Debug) {
		t = transport.NewLogger(t)
	}

	// hoisted this out of ggcr to avoid the double wrapping
	t = transport.NewRetry(t, transport.WithRetryPredicate(defaultRetryPredicate), transport.WithRetryStatusCodes(retryableStatusCodes...))

	h.Lock()
	pr, ok := h.pings[reg.String()]
	h.Unlock()
	if !ok {
		logs.Debug.Printf("missed ping for %q", reg.String())
		pr, err = transport.Ping(r.Context(), reg, t)
		if err != nil {
			return nil, err
		}
		h.Lock()
		logs.Debug.Printf("set ping for %q to %v", reg.String(), pr)
		h.pings[reg.String()] = pr
		h.Unlock()
	} else {
		logs.Debug.Printf("got ping for %q", reg.String())
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
