package apk

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"chainguard.dev/sdk/sts"
	"golang.org/x/time/rate"
	"google.golang.org/api/idtoken"
)

// This was shamelessly forked from apko to avoid depending on things.

type Authenticator interface {
	AddAuth(ctx context.Context, req *http.Request) error
}

// NewChainguardIdentityAuth returns an Authenticator that authorizes
// requests as the given assumeable identity.
//
// The identity is a UIDP of a Chainguard Identity.
// Issuer is usually https://issuer.enforce.dev.
// Audience is usually https://apk.cgr.dev.
func NewChainguardIdentityAuth(identity, issuer, audience string) Authenticator {
	return &cgAuth{
		id:  identity,
		iss: issuer,
		aud: audience,
	}
}

type cgAuth struct {
	id, iss, aud string

	sometimes rate.Sometimes
	cgtok     string
	cgerr     error
}

func (a *cgAuth) AddAuth(ctx context.Context, req *http.Request) error {
	if a.id == "" {
		return nil
	}
	if req.Host != strings.TrimPrefix(a.aud, "https://") {
		return nil
	}

	a.sometimes.Do(func() {
		a.cgerr = nil
		ts, err := idtoken.NewTokenSource(ctx, a.iss)
		if err != nil {
			a.cgerr = fmt.Errorf("creating token source: %w", err)
			return
		}
		tok, err := ts.Token()
		if err != nil {
			a.cgerr = fmt.Errorf("getting token: %w", err)
			return
		}
		ctok, err := sts.Exchange(ctx, a.iss, a.aud, tok.AccessToken, sts.WithIdentity(a.id))
		if err != nil {
			a.cgerr = fmt.Errorf("exchanging token: %w", err)
		}
		a.cgtok = ctok
	})
	if a.cgerr != nil {
		return a.cgerr
	}
	req.SetBasicAuth("user", a.cgtok)
	return nil
}
