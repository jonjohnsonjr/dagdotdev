package chainguard

import (
	"fmt"
	"net/url"
	"strings"
)

type Identity struct {
	ID, Issuer, Audience string
}

func ParseIdentity(raw string) (*Identity, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}

	if u.Scheme != "chainguard" {
		return nil, fmt.Errorf("invalid scheme %q", u.Scheme)
	}

	iss := u.Query().Get("iss")
	if iss == "" {
		return nil, fmt.Errorf("missing issuer query parameter")
	}
	if !strings.HasPrefix(iss, "https://") {
		iss = "https://" + iss
	}
	return &Identity{
		ID:       u.User.Username(),
		Issuer:   iss,
		Audience: u.Hostname(),
	}, nil
}
