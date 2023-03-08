package explore

import (
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func (h *handler) maybeOauthErr(w http.ResponseWriter, r *http.Request, err error) error {
	if h.oauth == nil {
		return err
	}

	var terr *transport.Error
	if !errors.As(err, &terr) {
		return err
	}
	if !isGoogle(terr.Request.URL.Host) {
		return err
	}
	if terr.StatusCode != http.StatusForbidden && terr.StatusCode != http.StatusUnauthorized {
		return err
	}

	data := OauthData{
		Error:    html.EscapeString(err.Error()),
		Redirect: h.oauth.AuthCodeURL(r.URL.String()),
	}

	if err := oauthTmpl.Execute(w, data); err != nil {
		return fmt.Errorf("failed to render oauth page: %w", err)
	}
	return nil
}

func (h *handler) oauthHandler(w http.ResponseWriter, r *http.Request) {
	if h.oauth == nil {
		return
	}

	qs := r.URL.Query()
	code := qs.Get("code")
	tok, err := h.oauth.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("Exchange: %v", err)
		return
	}
	if debug {
		log.Printf("tok = %v", tok)
	}

	state := qs.Get("state")
	u, err := url.ParseRequestURI(state)
	if err != nil {
		log.Printf("ParseRequestURI: %v", err)
		return
	}
	if tok.AccessToken != "" {
		cookie := &http.Cookie{
			Name:     "access_token",
			Value:    tok.AccessToken,
			Expires:  tok.Expiry,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)
	}
	if tok.RefreshToken != "" {
		cookie := &http.Cookie{
			Name:     "refresh_token",
			Value:    tok.RefreshToken,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)
	}

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func buildOauth() *oauth2.Config {
	ClientID := os.Getenv("CLIENT_ID")
	ClientSecret := os.Getenv("CLIENT_SECRET")
	RedirectURL := os.Getenv("REDIRECT_URL")

	if ClientID != "" && ClientSecret != "" {
		return &oauth2.Config{
			ClientID:     ClientID,
			ClientSecret: ClientSecret,
			RedirectURL:  RedirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/cloud-platform.read-only",
			},
			Endpoint: google.Endpoint,
		}
	}

	return nil
}
