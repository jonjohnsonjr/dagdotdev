package explore

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLexer(t *testing.T) {
	b := `{"foo":[{}, {"bar":{"foo.bar":["aGVsbG8=", "world"]}}]}`
	input := `.foo[1].bar["foo.bar"][0] | base64 -d`
	want := []byte("hello")

	got, _, err := evalBytes(input, []byte(b))
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%s", diff)
	}
}
