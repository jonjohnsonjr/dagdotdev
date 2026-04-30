package name

import (
	"errors"
	"testing"
)

func TestRegistryScheme(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		{"127.0.0.1:5000", "http"},
		{"localhost:5000", "http"},
		{"foo.local", "http"},
		{"foo.localhost", "http"},
		{"[::1]:5000", "http"},
		{"10.1.2.3:5000", "http"},
		{"172.16.0.1:5000", "http"},
		{"192.168.1.1", "http"},
		{"index.docker.io", "https"},
		{"gcr.io", "https"},
		{"example.com:5000", "https"},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			r, err := NewRegistry(tc.host)
			if err != nil {
				t.Fatalf("NewRegistry(%q): %v", tc.host, err)
			}
			if got := r.Scheme(); got != tc.want {
				t.Errorf("Scheme(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

func TestNewRegistryRejectsInvalid(t *testing.T) {
	for _, in := range []string{"with spaces", "two//slashes"} {
		if _, err := NewRegistry(in); err == nil {
			t.Errorf("NewRegistry(%q) accepted invalid input", in)
		}
	}
}

func TestNewRepository(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantReg     string
		wantRepoStr string
		wantName    string
	}{
		{
			name:        "registry_only_bare_hostname",
			in:          "gcr.io",
			wantReg:     "gcr.io",
			wantRepoStr: "",
			wantName:    "gcr.io/",
		},
		{
			name:        "registry_and_repo",
			in:          "gcr.io/project/image",
			wantReg:     "gcr.io",
			wantRepoStr: "project/image",
			wantName:    "gcr.io/project/image",
		},
		{
			name:        "implicit_namespace_for_dockerhub",
			in:          "alpine",
			wantReg:     DefaultRegistry,
			wantRepoStr: "library/alpine",
			wantName:    DefaultRegistry + "/library/alpine",
		},
		{
			name:        "explicit_namespace_dockerhub",
			in:          "library/alpine",
			wantReg:     DefaultRegistry,
			wantRepoStr: "library/alpine",
			wantName:    DefaultRegistry + "/library/alpine",
		},
		{
			name:        "loopback_with_port",
			in:          "127.0.0.1:5000/foo",
			wantReg:     "127.0.0.1:5000",
			wantRepoStr: "foo",
			wantName:    "127.0.0.1:5000/foo",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRepository(tc.in)
			if err != nil {
				t.Fatalf("NewRepository(%q): %v", tc.in, err)
			}
			if got := r.RegistryStr(); got != tc.wantReg {
				t.Errorf("RegistryStr() = %q, want %q", got, tc.wantReg)
			}
			if got := r.RepositoryStr(); got != tc.wantRepoStr {
				t.Errorf("RepositoryStr() = %q, want %q", got, tc.wantRepoStr)
			}
			if got := r.Name(); got != tc.wantName {
				t.Errorf("Name() = %q, want %q", got, tc.wantName)
			}
		})
	}
}

func TestNewRepositoryEmpty(t *testing.T) {
	if _, err := NewRepository(""); err == nil {
		t.Errorf("NewRepository(\"\") should fail")
	}
}

func TestNewTag(t *testing.T) {
	cases := []struct {
		in       string
		wantRepo string
		wantTag  string
	}{
		{"alpine", "index.docker.io/library/alpine", "latest"},
		{"alpine:3.19", "index.docker.io/library/alpine", "3.19"},
		{"gcr.io/project/image:v1.2.3", "gcr.io/project/image", "v1.2.3"},
		{"127.0.0.1:5000/foo:bar", "127.0.0.1:5000/foo", "bar"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			tg, err := NewTag(tc.in)
			if err != nil {
				t.Fatalf("NewTag(%q): %v", tc.in, err)
			}
			if got := tg.Repository.Name(); got != tc.wantRepo {
				t.Errorf("Repository.Name() = %q, want %q", got, tc.wantRepo)
			}
			if got := tg.TagStr(); got != tc.wantTag {
				t.Errorf("TagStr() = %q, want %q", got, tc.wantTag)
			}
			if got := tg.Identifier(); got != tc.wantTag {
				t.Errorf("Identifier() = %q, want %q", got, tc.wantTag)
			}
		})
	}
}

func TestNewDigest(t *testing.T) {
	const sha = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	d, err := NewDigest("gcr.io/project/image@" + sha)
	if err != nil {
		t.Fatalf("NewDigest: %v", err)
	}
	if got := d.DigestStr(); got != sha {
		t.Errorf("DigestStr() = %q, want %q", got, sha)
	}
	if got := d.Identifier(); got != sha {
		t.Errorf("Identifier() = %q, want %q", got, sha)
	}
	if got := d.Repository.Name(); got != "gcr.io/project/image" {
		t.Errorf("Repository.Name() = %q", got)
	}
	if got := d.Name(); got != "gcr.io/project/image@"+sha {
		t.Errorf("Name() = %q", got)
	}
}

func TestNewDigestRejectsBadInputs(t *testing.T) {
	cases := []string{
		"",
		"no-at-symbol",
		"too@many@ats@here",
		"gcr.io/x@md5:abc",                                                                          // unsupported algo
		"gcr.io/x@sha256:zz0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",        // non-hex
		"gcr.io/x@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",           // 63 chars
		"gcr.io/x@sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",          // wrong length
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, err := NewDigest(tc); err == nil {
				t.Errorf("NewDigest(%q) should fail", tc)
			}
		})
	}
}

func TestParseReferenceTagOrDigest(t *testing.T) {
	const sha = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	d, err := ParseReference("gcr.io/x/y@" + sha)
	if err != nil {
		t.Fatalf("ParseReference digest: %v", err)
	}
	if _, ok := d.(Digest); !ok {
		t.Errorf("ParseReference digest: got %T, want Digest", d)
	}

	tg, err := ParseReference("gcr.io/x/y:v1")
	if err != nil {
		t.Fatalf("ParseReference tag: %v", err)
	}
	if _, ok := tg.(Tag); !ok {
		t.Errorf("ParseReference tag: got %T, want Tag", tg)
	}
}

func TestParseReferenceErrors(t *testing.T) {
	if _, err := ParseReference(""); err == nil {
		t.Errorf("ParseReference(\"\") should fail")
	}
}

func TestErrBadName(t *testing.T) {
	err := newErrBadName("oops %s", "value")
	var bad *ErrBadName
	if !errors.As(err, &bad) {
		t.Fatalf("expected ErrBadName, got %T", err)
	}
	if got := err.Error(); got != "oops value" {
		t.Errorf("Error() = %q, want %q", got, "oops value")
	}
	if !errors.Is(err, &ErrBadName{}) {
		t.Errorf("errors.Is should match a sentinel ErrBadName")
	}
}

