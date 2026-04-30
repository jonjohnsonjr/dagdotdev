package redact

import (
	"context"
	"errors"
	"net/url"
	"testing"
)

func TestContext(t *testing.T) {
	ctx := context.Background()
	ok, _ := FromContext(ctx)
	if ok {
		t.Errorf("empty context should not have a redaction reason")
	}

	ctx = NewContext(ctx, "for tests")
	ok, reason := FromContext(ctx)
	if !ok || reason != "for tests" {
		t.Errorf("FromContext = (%v, %q), want (true, \"for tests\")", ok, reason)
	}
}

func TestURLRedactsUnknownParams(t *testing.T) {
	u, err := url.Parse("https://gcr.io/v2/foo?secret=hunter2&scope=registry:catalog:*&token=abc&n=10")
	if err != nil {
		t.Fatal(err)
	}
	got := URL(u)
	gotQs := got.Query()
	if gotQs.Get("secret") != "REDACTED" {
		t.Errorf("secret = %q, want REDACTED", gotQs.Get("secret"))
	}
	if gotQs.Get("token") != "REDACTED" {
		t.Errorf("token = %q, want REDACTED", gotQs.Get("token"))
	}
	if gotQs.Get("scope") != "registry:catalog:*" {
		t.Errorf("scope was unexpectedly redacted: %q", gotQs.Get("scope"))
	}
	if gotQs.Get("n") != "10" {
		t.Errorf("n was unexpectedly redacted: %q", gotQs.Get("n"))
	}
	// The original URL must not be mutated.
	if u.Query().Get("secret") != "hunter2" {
		t.Errorf("original URL was mutated: %v", u)
	}
}

func TestURLAllowlist(t *testing.T) {
	allow := []string{"scope", "service", "mount", "from", "digest", "n", "last"}
	for _, k := range allow {
		t.Run(k, func(t *testing.T) {
			u, _ := url.Parse("https://example.com/path?" + k + "=value")
			if got := URL(u).Query().Get(k); got != "value" {
				t.Errorf("%s redacted unexpectedly: %q", k, got)
			}
		})
	}
}

func TestErrorRedactsURLError(t *testing.T) {
	const original = "https://gcr.io/v2/foo?token=hunter2"
	uerr := &url.Error{Op: "Get", URL: original, Err: errors.New("boom")}
	got := Error(uerr)
	var redacted *url.Error
	if !errors.As(got, &redacted) {
		t.Fatalf("expected *url.Error, got %T", got)
	}
	if redacted.URL == original {
		t.Errorf("URL not redacted: %q", redacted.URL)
	}
	parsed, _ := url.Parse(redacted.URL)
	if parsed.Query().Get("token") != "REDACTED" {
		t.Errorf("token not REDACTED in %q", redacted.URL)
	}
}

func TestErrorPassthrough(t *testing.T) {
	if Error(nil) != nil {
		t.Errorf("Error(nil) should return nil")
	}
	plain := errors.New("plain")
	if Error(plain) != plain {
		t.Errorf("non-url.Error should be returned unchanged")
	}
	// url.Error wrapping a non-parseable URL should be returned unchanged.
	uerr := &url.Error{Op: "Get", URL: "://bad", Err: errors.New("boom")}
	if Error(uerr) != uerr {
		t.Errorf("url.Error with unparseable URL should be returned unchanged")
	}
}
