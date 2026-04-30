// Copyright 2018 Google LLC All Rights Reserved.
// Licensed under the Apache License, Version 2.0.

package authn

// Authenticator is used to authenticate Docker transports.
type Authenticator interface {
	// Authorization returns the value to use in an http transport's
	// Authorization header.
	Authorization() (*AuthConfig, error)
}

// AuthorizerFunc adapts a plain function to the Authenticator interface so
// callers can build an Authenticator from any token source (oauth2 / idtoken
// / etc.) without us having to import the underlying SDK.
type AuthorizerFunc func() (*AuthConfig, error)

// Authorization implements Authenticator.
func (f AuthorizerFunc) Authorization() (*AuthConfig, error) { return f() }

// AuthConfig is the credential blob used by transport.* to build the right
// Authorization header (Bearer / Basic / pre-encoded). Mirrors the subset of
// docker/cli's AuthConfig that we actually consume.
type AuthConfig struct {
	Username      string
	Password      string
	Auth          string
	IdentityToken string
	RegistryToken string
}
