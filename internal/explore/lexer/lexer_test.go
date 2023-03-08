package lexer

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLexer(t *testing.T) {

	tc := []Item{{
		ItemAccessor, "foo",
	}, {
		ItemIndex, "1",
	}, {
		ItemAccessor, "bar",
	}, {
		ItemAccessor, "foo.bar",
	}, {
		ItemIndex, "0",
	}, {
		ItemSentinel, "base64 -d",
	}, {
		ItemEOF, "",
	}}
	l := Lex("test", `.foo[1].bar["foo.bar"][0] | base64 -d`)

	for idx, want := range tc {
		got := l.NextItem()
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("[%d]: %s", idx, diff)
		}
	}
}
