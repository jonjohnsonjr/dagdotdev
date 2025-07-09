package apk

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"chainguard.dev/sdk/sts"
	"github.com/jonjohnsonjr/dagdotdev/internal/chainguard"
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
		id:        identity,
		iss:       issuer,
		aud:       audience,
		sometimes: rate.Sometimes{Interval: 30 * time.Minute},
	}
}

// NewChainguardIdentityAuthFromURL parses a URL of the form uidp@cgr.dev?iss=issuer.enforce.dev
func NewChainguardIdentityAuthFromURL(raw string) (Authenticator, error) {
	id, err := chainguard.ParseIdentity(raw)
	if err != nil {
		return nil, err
	}

	return NewChainguardIdentityAuth(id.ID, id.Issuer, id.Audience), nil
}

func NewChainguardMultiKeychain(raw string, defaultIssuer string, defaultAudience string) (Authenticator, error) {
	var ks []Authenticator
	for _, s := range strings.Split(raw, ",") {
		if strings.HasPrefix(s, "chainguard://") {
			k, err := NewChainguardIdentityAuthFromURL(s)
			if err != nil {
				return nil, fmt.Errorf("parsing %q: %w", s, err)
			}
			ks = append(ks, k)
		} else {
			// Not URL format, fallback to basic identity format.
			ks = append(ks, NewChainguardIdentityAuth(s, defaultIssuer, defaultAudience))
		}
	}
	return NewMultiAuthenticator(ks...), nil
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

type multiAuthenticator struct {
	auths []Authenticator
}

func NewMultiAuthenticator(auth ...Authenticator) Authenticator {
	return &multiAuthenticator{auths: auth}
}

func (a *multiAuthenticator) AddAuth(ctx context.Context, req *http.Request) error {
	for _, auth := range a.auths {
		if err := auth.AddAuth(ctx, req); err != nil {
			return err
		}
		if req.Header.Get("Authorization") != "" {
			// Auth was set, we're done.
			return nil
		}
	}
	return nil
}
