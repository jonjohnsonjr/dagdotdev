package explore

import (
	"log"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"golang.org/x/oauth2"
)

func isGoogle(host string) bool {
	if host != "gcr.io" && !strings.HasSuffix(host, ".gcr.io") && !strings.HasSuffix(host, ".pkg.dev") && !strings.HasSuffix(host, ".google.com") {
		return false
	}
	return true
}

// TODO: ugh
func (h *handler) googleOptions(w http.ResponseWriter, r *http.Request, repo string) []google.Option {
	ctx := r.Context()

	opts := []google.Option{}
	opts = append(opts, google.WithContext(ctx))
	if repo == "mirror.gcr.io" {
		t := remote.DefaultTransport
		t = transport.NewRetry(t)
		t = transport.NewUserAgent(t, h.userAgent)
		if r.URL.Query().Get("trace") != "" {
			t = transport.NewTracer(t)
		}
		t = transport.Wrap(t)
		opts = append(opts, google.WithTransport(t))
		return opts
	}
	auth := authn.Anonymous
	if h.keychain != nil {
		ref, err := name.NewRepository(repo)
		if err == nil {
			maybeAuth, err := h.keychain.Resolve(ref)
			if err == nil {
				auth = maybeAuth
			} else {
				logs.Debug.Printf("Resolve(%q) = %v", repo, err)
			}
		} else {
			logs.Debug.Printf("NewRepository(%q) = %v", repo, err)
		}
	}

	parsed, err := name.NewRepository(repo)
	if err == nil && isGoogle(parsed.Registry.String()) {
		if at, err := r.Cookie("access_token"); err == nil {
			tok := &oauth2.Token{
				AccessToken: at.Value,
				Expiry:      at.Expires,
			}
			if rt, err := r.Cookie("refresh_token"); err == nil {
				tok.RefreshToken = rt.Value
			}
			if h.oauth != nil {
				ts := h.oauth.TokenSource(r.Context(), tok)
				auth = google.NewTokenSourceAuthenticator(ts)
			}
		}
	}

	opts = append(opts, google.WithAuth(auth))

	if t, err := h.transportFromCookie(w, r, repo, auth); err != nil {
		log.Printf("failed to get transport from cookie: %v", err)
	} else {
		opts = append(opts, google.WithTransport(t))
	}

	return opts
}
