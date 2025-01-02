package explore

import "testing"

func TestNewChainguardIdentityAuthFromURL(t *testing.T) {
	auth, err := NewChainguardIdentityAuthFromURL("chainguard://uidp@apk.cgr.dev?iss=issuer.enforce.dev")
	if err != nil {
		t.Fatal(err)
	}
	cgauth, ok := auth.(*keychain)
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

func TestNewChainguardMultiKeychain(t *testing.T) {
	_, err := NewChainguardMultiKeychain("uidp,chainguard://uidp@cgr.dev?iss=issuer.enforce.dev", "foo", "bar")
	if err != nil {
		t.Fatalf("NewChainguardMultiKeychain() error = %v", err)
	}
}
