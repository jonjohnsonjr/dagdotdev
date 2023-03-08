package explore

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

type CookieValue struct {
	Reg           string
	PingResp      *transport.PingResp
	Repo          string
	TokenResponse *transport.TokenResponse
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

	var (
		pr  *transport.PingResp
		tok *transport.TokenResponse
	)
	if regCookie, err := r.Cookie("registry_token"); err == nil {
		b, err := base64.URLEncoding.DecodeString(regCookie.Value)
		if err != nil {
			return nil, err
		}
		var v CookieValue
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, err
		}
		if v.Reg == reg.String() {
			pr = v.PingResp
			if v.Repo == repo {
				tok = v.TokenResponse
			}
		}
	}

	t := remote.DefaultTransport
	t = transport.NewRetry(t)
	if r.URL.Query().Get("trace") != "" {
		t = transport.NewTracer(t)
	}

	if pr == nil {
		if cpr, ok := h.pings[reg.String()]; ok {
			if debug {
				log.Printf("cached ping: %v", cpr)
			}
			pr = cpr
		} else {
			if debug {
				log.Printf("pinging %s", reg.String())
			}
			pr, err = transport.Ping(r.Context(), reg, t)
			if err != nil {
				return nil, err
			}
			h.pings[reg.String()] = pr
		}
	}

	if tok == nil {
		if debug {
			log.Printf("getting token %s", reg.String())
		}
		t, tok, err = transport.NewBearer(r.Context(), pr, reg, auth, t, scopes)
		if err != nil {
			return nil, err
		}

		// Probably no auth needed.
		if tok == nil {
			return t, nil
		}

		// Clear this to make cookies smaller.
		tok.AccessToken = ""

		v := &CookieValue{
			Reg:           reg.String(),
			PingResp:      pr,
			Repo:          repo,
			TokenResponse: tok,
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		cv := base64.URLEncoding.EncodeToString(b)
		cookie := &http.Cookie{
			Name:     "registry_token",
			Value:    cv,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
		if tok.ExpiresIn == 0 {
			tok.ExpiresIn = 60
		}
		exp := time.Now().Add(time.Second * time.Duration(tok.ExpiresIn))
		cookie.Expires = exp
		http.SetCookie(w, cookie)
	} else {
		if debug {
			log.Printf("restoring bearer %s", reg.String())
		}
		t, err = transport.OldBearer(pr, tok, reg, auth, t, scopes)
		if err != nil {
			return nil, err
		}
	}

	return t, nil
}
