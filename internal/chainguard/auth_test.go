package chainguard

import (
	"testing"
)

func TestNewChainguardIdentityAuthFromURL(t *testing.T) {
	cases := []struct {
		rawURL  string
		wantErr bool
		wantID  string
		wantIss string
		wantAud string
	}{
		{
			rawURL:  "chainguard://uidp@cgr.dev?iss=issuer.enforce.dev",
			wantErr: false,
			wantID:  "uidp",
			wantIss: "https://issuer.enforce.dev",
			wantAud: "cgr.dev",
		},
		{
			rawURL:  "invalid-url",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.rawURL, func(t *testing.T) {
			got, err := ParseIdentity(tc.rawURL)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NewChainguardIdentityAuthFromURL() error = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil {
				if got.ID != tc.wantID {
					t.Errorf("id = %v, want %v", got.ID, tc.wantID)
				}
				if got.Issuer != tc.wantIss {
					t.Errorf("iss = %v, want %v", got.Issuer, tc.wantIss)
				}
				if got.Audience != tc.wantAud {
					t.Errorf("aud = %v, want %v", got.Audience, tc.wantAud)
				}
			}
		})
	}
}
