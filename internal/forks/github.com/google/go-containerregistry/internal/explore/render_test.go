package explore

import (
	"bytes"
	"net/url"
	"testing"
)

func TestRenderJSON(t *testing.T) {
	u, err := url.Parse("http://explore.example.com?foo=bar")
	if err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	output := &jsonOutputter{
		w:     &w,
		u:     u,
		fresh: []bool{},
		repo:  "example.com/foo/bar",
	}

	b := []byte(`{"mediaType":"application/vnd.docker.distribution.manifest.v2+json", "schemaVersion":2,"layers":[]}`)

	if err := renderJSON(output, b); err != nil {
		t.Fatal(err)
	}
}
