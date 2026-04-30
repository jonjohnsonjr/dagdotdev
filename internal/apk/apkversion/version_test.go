package apkversion

import "testing"

func TestCompareVersions(t *testing.T) {
	// Cases mirroring apk-tools' test/version.test plus a few from common
	// Wolfi / Alpine package upgrades, exercising every part of the parser.
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.1", "1.0", 1},
		{"1.0.1", "1.0", 1},
		{"1.0", "1.0.1", -1},
		{"1.0a", "1.0", 1},
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0b", -1},
		{"1.0_alpha1", "1.0_alpha2", -1},
		{"1.0_alpha", "1.0_beta", -1},
		{"1.0_beta", "1.0_pre", -1},
		{"1.0_pre", "1.0_rc", -1},
		{"1.0_rc", "1.0", -1},
		{"1.0", "1.0_rc", 1},
		{"1.0_p1", "1.0", 1},
		{"1.0_p1", "1.0_p2", -1},
		{"1.0-r1", "1.0-r2", -1},
		{"1.0-r2", "1.0-r1", 1},
		{"1.0-r1", "1.0", 1},
		{"1.2.3", "1.2.3-r4", -1},
		{"3.0.0_alpha1-r0", "3.0.0-r0", -1},
	}
	for _, tc := range cases {
		va, err := ParseVersion(tc.a)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", tc.a, err)
		}
		vb, err := ParseVersion(tc.b)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", tc.b, err)
		}
		if got := CompareVersions(va, vb); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestParseVersion_Invalid(t *testing.T) {
	cases := []string{
		"",
		"abc",
		"1.0_unknown",
	}
	for _, tc := range cases {
		if _, err := ParseVersion(tc); err == nil {
			t.Errorf("ParseVersion(%q) succeeded; want error", tc)
		}
	}
}
