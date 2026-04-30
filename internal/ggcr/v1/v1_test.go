package v1

import (
	"bytes"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/json"
	"strings"
	"testing"
)

func TestSHA256(t *testing.T) {
	// Empty input has the well-known sha256 of "".
	const wantEmpty = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	h, n, err := SHA256(strings.NewReader(""))
	if err != nil {
		t.Fatalf("SHA256(empty): %v", err)
	}
	if got := h.String(); got != wantEmpty {
		t.Errorf("empty SHA256 = %q, want %q", got, wantEmpty)
	}
	if n != 0 {
		t.Errorf("empty size = %d, want 0", n)
	}

	const wantHello = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	h, n, err = SHA256(strings.NewReader("hello world"))
	if err != nil {
		t.Fatalf("SHA256(hello): %v", err)
	}
	if got := h.String(); got != wantHello {
		t.Errorf("hello SHA256 = %q, want %q", got, wantHello)
	}
	if n != 11 {
		t.Errorf("hello size = %d, want 11", n)
	}
}

func TestNewHash(t *testing.T) {
	const validSha256 = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	h, err := NewHash(validSha256)
	if err != nil {
		t.Fatalf("NewHash: %v", err)
	}
	if h.Algorithm != "sha256" || h.Hex != strings.TrimPrefix(validSha256, "sha256:") {
		t.Errorf("parsed = %+v", h)
	}
	if got := h.String(); got != validSha256 {
		t.Errorf("String() = %q, want %q", got, validSha256)
	}

	const validSha512 = "sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := NewHash(validSha512); err != nil {
		t.Errorf("NewHash sha512: %v", err)
	}
}

func TestNewHashErrors(t *testing.T) {
	cases := []string{
		"",
		"missing-colon",
		"too:many:colons",
		"md5:abc", // unsupported algorithm
		"sha256:nothex000000000000000000000000000000000000000000000000000000000000",
		"sha256:short",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := NewHash(in); err == nil {
				t.Errorf("NewHash(%q) should fail", in)
			}
		})
	}
}

func TestHashJSON(t *testing.T) {
	const sha = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	h, err := NewHash(sha)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	want := `"` + sha + `"`
	if string(b) != want {
		t.Errorf("marshal = %s, want %s", b, want)
	}
	var got Hash
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != h {
		t.Errorf("roundtrip mismatch: %+v vs %+v", got, h)
	}

	if err := json.Unmarshal([]byte(`"not-a-hash"`), &got); err == nil {
		t.Errorf("Unmarshal of bad hash should fail")
	}
	if err := json.Unmarshal([]byte(`not json`), &got); err == nil {
		t.Errorf("Unmarshal of unquoted should fail")
	}
}

func TestHasher(t *testing.T) {
	if h, err := Hasher("sha256"); err != nil || h == nil || h.Size() != 32 {
		t.Errorf("Hasher(sha256) = %v, err = %v", h, err)
	}
	if h, err := Hasher("sha512"); err != nil || h == nil || h.Size() != 64 {
		t.Errorf("Hasher(sha512) = %v, err = %v", h, err)
	}
	if _, err := Hasher("md5"); err == nil {
		t.Errorf("Hasher(md5) should fail")
	}
}

func TestParseManifest(t *testing.T) {
	body := []byte(`{
		"schemaVersion": 2,
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": {
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"size": 100
		},
		"layers": [
			{
				"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
				"digest": "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
				"size": 200
			}
		],
		"annotations": {"org.opencontainers.image.created": "2024-01-01T00:00:00Z"}
	}`)
	m, err := ParseManifest(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.SchemaVersion != 2 {
		t.Errorf("SchemaVersion = %d", m.SchemaVersion)
	}
	if string(m.MediaType) != "application/vnd.oci.image.manifest.v1+json" {
		t.Errorf("MediaType = %q", m.MediaType)
	}
	if m.Config.Size != 100 {
		t.Errorf("Config.Size = %d", m.Config.Size)
	}
	if len(m.Layers) != 1 || m.Layers[0].Size != 200 {
		t.Errorf("Layers = %+v", m.Layers)
	}
	if m.Annotations["org.opencontainers.image.created"] != "2024-01-01T00:00:00Z" {
		t.Errorf("Annotations = %+v", m.Annotations)
	}
}

func TestParseManifestError(t *testing.T) {
	if _, err := ParseManifest(strings.NewReader("not json")); err == nil {
		t.Errorf("ParseManifest of garbage should fail")
	}
}
