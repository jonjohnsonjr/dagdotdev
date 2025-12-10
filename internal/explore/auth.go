package explore

import (
	"context"
	"fmt"
	"log"
	"time"

	"chainguard.dev/sdk/sts"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/authn"
	"golang.org/x/time/rate"
	"google.golang.org/api/idtoken"
)

func NewChainguardIdentityAuth(identity, issuer, audience string) authn.Keychain {
	log.Printf("NewChainguardIdentityAuth(%q, %q, %q)", identity, issuer, audience)
	return &keychain{
		id:        identity,
		iss:       issuer,
		aud:       audience,
		sometimes: rate.Sometimes{Interval: 30 * time.Minute},
	}
}

type keychain struct {
	id, iss, aud string

	sometimes rate.Sometimes
	cgtok     string
	cgerr     error
}

func (k *keychain) Resolve(res authn.Resource) (authn.Authenticator, error) {
	return k.ResolveContext(context.Background(), res)
}

func (k *keychain) ResolveContext(ctx context.Context, res authn.Resource) (authn.Authenticator, error) {
	log.Printf("chainguard.Keychain.Resolve(%q)", res.String())

	if k.id == "" {
		log.Printf("k.id is empty")
		return authn.Anonymous, nil
	}

	if res.RegistryStr() != "cgr.dev" {
		log.Printf("%q != %q", res.RegistryStr(), "cgr.dev")
		return authn.Anonymous, nil
	}

	k.sometimes.Do(func() {
		log.Printf("chainguard.Keychain.sometimes.Do()")

		k.cgerr = nil
		ts, err := idtoken.NewTokenSource(ctx, k.iss)
		if err != nil {
			k.cgerr = fmt.Errorf("creating token source: %w", err)
			return
		}
		tok, err := ts.Token()
		if err != nil {
			k.cgerr = fmt.Errorf("getting token: %w", err)
			return
		}
		ctok, err := sts.Exchange(ctx, k.iss, k.aud, tok.AccessToken, sts.WithIdentity(k.id))
		if err != nil {
			k.cgerr = fmt.Errorf("exchanging token: %w", err)
		}
		k.cgtok = ctok
	})

	if k.cgerr != nil {
		log.Printf("chainguard.Keychain.Resolve = %v", k.cgerr)
		return nil, k.cgerr
	}

	log.Printf("chainguard.Keychain.Resolve | len: %d", len(k.cgtok))
	return &authn.Basic{
		Username: "_token",
		Password: k.cgtok,
	}, nil
}
