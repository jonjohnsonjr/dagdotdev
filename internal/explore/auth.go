package explore

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"chainguard.dev/sdk/sts"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/jonjohnsonjr/dagdotdev/internal/chainguard"
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

// NewChainguardIdentityAuthFromURL parses a URL of the form uidp@cgr.dev?iss=issuer.enforce.dev
func NewChainguardIdentityAuthFromURL(raw string) (authn.Keychain, error) {
	id, err := chainguard.ParseIdentity(raw)
	if err != nil {
		return nil, err
	}
	return NewChainguardIdentityAuth(id.ID, id.Issuer, id.Audience), nil
}

func NewChainguardMultiKeychain(raw string, defaultIssuer string, defaultAudience string) (authn.Keychain, error) {
	var ks []authn.Keychain
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
	return authn.NewMultiKeychain(ks...), nil
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

	if res.RegistryStr() != k.aud {
		log.Printf("%q != %q", res.RegistryStr(), k.aud)
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
