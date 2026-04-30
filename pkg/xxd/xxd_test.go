package xxd

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriter(t *testing.T) {
	cases := []struct {
		name string
		in   string
		size int64
		want string
	}{
		{
			name: "empty",
			in:   "",
			size: 0,
			want: "",
		},
		{
			name: "one_full_line",
			in:   "0123456789abcdef",
			size: 16,
			want: "00000000: 3031 3233 3435 3637 3839 6162 6364 6566  0123456789abcdef\n",
		},
		{
			name: "partial_line_pads_hex_columns",
			in:   "hi!",
			size: 3,
			want: "00000000: 6869 21                                  hi!",
		},
		{
			name: "html_escapes",
			in:   "<&>\"'",
			size: 5,
			want: "00000000: 3c26 3e22 27                             &lt;&amp;&gt;&#34;&#39;",
		},
		{
			name: "nonprintable_dots",
			in:   "\x00\x01\x02\x03",
			size: 4,
			want: "00000000: 0001 0203                                ....",
		},
		{
			name: "size_truncates_input",
			in:   "abcdefghij",
			size: 4,
			want: "00000000: 6162 6364                                abcd",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf, tc.size)
			if _, err := w.Write([]byte(tc.in)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got := buf.String()
			if got != tc.want {
				t.Errorf("xxd output mismatch\n--- want ---\n%q\n--- got ---\n%q", tc.want, got)
			}
		})
	}
}

func TestWriterTwoLines(t *testing.T) {
	in := strings.Repeat("A", 17) // 16 + 1 → one full + one partial
	want := "00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA\n" +
		"00000010: 41                                       A"
	var buf bytes.Buffer
	w := NewWriter(&buf, 17)
	if _, err := w.Write([]byte(in)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := buf.String(); got != want {
		t.Errorf("two-line mismatch\n--- want ---\n%q\n--- got ---\n%q", want, got)
	}
}
