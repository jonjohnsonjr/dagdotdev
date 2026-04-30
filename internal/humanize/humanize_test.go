package humanize

import "testing"

func TestIBytes(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{9, "9 B"},
		{10, "10 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1500, "1.5 KiB"},
		{1024 * 1024, "1.0 MiB"},
		{2*1024*1024 + 512*1024, "2.5 MiB"},
		{1024 * 1024 * 1024, "1.0 GiB"},
		{1024 * 1024 * 1024 * 1024, "1.0 TiB"},
		{1024 * 1024 * 1024 * 1024 * 1024, "1.0 PiB"},
		{1024 * 1024 * 1024 * 1024 * 1024 * 1024, "1.0 EiB"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			got := IBytes(tc.in)
			if got != tc.want {
				t.Errorf("IBytes(%d) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
