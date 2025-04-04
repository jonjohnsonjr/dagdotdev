package apk

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockAuth struct {
	token string
}

func (m *mockAuth) AddAuth(ctx context.Context, req *http.Request) error {
	if m.token != "" {
		req.SetBasicAuth("user", m.token)
	}
	return nil
}

func TestNewMultiAuthenticator(t *testing.T) {
	auth := NewMultiAuthenticator(&mockAuth{}, &mockAuth{token: "foo"})
	req := httptest.NewRequest("GET", "/", nil)
	if err := auth.AddAuth(context.Background(), req); err != nil {
		t.Fatalf("NewMultiAuthenticator() error = %v", err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:foo"))
	got := req.Header.Get("Authorization")
	if got != want {
		t.Errorf("Authorization = %v, want %v", string(got), want)
	}
}

func TestNewChainguardMultiKeychain(t *testing.T) {
	_, err := NewChainguardMultiKeychain("uidp,chainguard://uidp@apk.cgr.dev?iss=issuer.enforce.dev", "foo", "bar")
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewChainguardIdentityAuthFromURL(t *testing.T) {
	auth, err := NewChainguardIdentityAuthFromURL("chainguard://uidp@apk.cgr.dev?iss=issuer.enforce.dev")
	if err != nil {
		t.Fatal(err)
	}
	cgauth, ok := auth.(*cgAuth)
	if !ok {
		t.Fatalf("NewChainguardIdentityAuthFromURL() = %T, want *cgAuth", auth)
	}

	if cgauth.id != "uidp" {
		t.Errorf("id = %v, want uidp", cgauth.id)
	}
	if cgauth.iss != "https://issuer.enforce.dev" {
		t.Errorf("iss = %v, want https://issuer.enforce.dev", cgauth.iss)
	}
	if cgauth.aud != "apk.cgr.dev" {
		t.Errorf("aud = %v, want apk.cgr.dev", cgauth.aud)
	}
}
