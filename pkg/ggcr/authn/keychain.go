// Copyright 2018 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/name"
)

// Resource represents a registry or repository that can be authenticated against.
type Resource interface {
	String() string
	RegistryStr() string
}

// Keychain resolves an image reference to a credential.
type Keychain interface {
	Resolve(Resource) (Authenticator, error)
}

// DefaultKeychain reads ~/.docker/config.json (or the Podman equivalent) and
// shells out to credential helpers when the config calls for one.
var DefaultKeychain Keychain = &defaultKeychain{}

// DefaultAuthKey is the legacy Docker Hub key in config.json.
const DefaultAuthKey = "https://" + name.DefaultRegistry + "/v1/"

type defaultKeychain struct {
	mu sync.Mutex
}

// Resolve implements Keychain.
func (dk *defaultKeychain) Resolve(target Resource) (Authenticator, error) {
	dk.mu.Lock()
	defer dk.mu.Unlock()

	cfg, err := loadDockerConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return Anonymous, nil
	}

	// Try the full target (with repo path) and then the bare registry. Docker
	// Hub gets aliased to its legacy key.
	for _, key := range []string{target.String(), target.RegistryStr()} {
		if key == name.DefaultRegistry {
			key = DefaultAuthKey
		}
		ac, ok, err := cfg.lookup(key)
		if err != nil {
			return nil, err
		}
		if ok {
			return FromConfig(ac), nil
		}
	}
	return Anonymous, nil
}

// dockerConfig is the subset of ~/.docker/config.json we use.
type dockerConfig struct {
	Auths       map[string]dockerAuth `json:"auths"`
	CredsStore  string                `json:"credsStore,omitempty"`
	CredHelpers map[string]string     `json:"credHelpers,omitempty"`
}

type dockerAuth struct {
	Auth          string `json:"auth,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
	RegistryToken string `json:"registrytoken,omitempty"`
}

// loadDockerConfig finds and parses the active config file. Order matches the
// existing behavior:
//  1. $HOME/.docker/config.json
//  2. $DOCKER_CONFIG/config.json (if env set)
//  3. $XDG_RUNTIME_DIR/containers/auth.json (Podman fallback)
//
// Returns nil, nil if no file is found.
func loadDockerConfig() (*dockerConfig, error) {
	var path string
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".docker/config.json")
		if fileExists(p) {
			path = p
		}
	}
	if path == "" {
		if dc := os.Getenv("DOCKER_CONFIG"); dc != "" {
			p := filepath.Join(dc, "config.json")
			if fileExists(p) {
				path = p
			}
		}
	}
	if path == "" {
		if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
			p := filepath.Join(xdg, "containers/auth.json")
			if fileExists(p) {
				path = p
			}
		}
	}
	if path == "" {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := &dockerConfig{}
	if err := json.NewDecoder(f).Decode(cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	// Decode any inline base64 auth into username/password.
	for k, ac := range cfg.Auths {
		if ac.Auth != "" {
			u, p, err := decodeAuth(ac.Auth)
			if err != nil {
				return nil, fmt.Errorf("parsing %s auth for %q: %w", path, k, err)
			}
			ac.Username = u
			ac.Password = p
			ac.Auth = ""
			cfg.Auths[k] = ac
		}
	}
	return cfg, nil
}

// lookup returns the AuthConfig for key, plus whether one was found. If a
// credential helper applies, it's executed; if not, the inline auths entry is
// used (with a fallback that matches by hostname only).
func (c *dockerConfig) lookup(key string) (AuthConfig, bool, error) {
	if helper := c.helperFor(key); helper != "" {
		ac, found, err := runCredentialHelper(helper, key)
		if err != nil {
			return AuthConfig{}, false, err
		}
		if found {
			return ac, true, nil
		}
		// Fall through: helper said "not found", try inline anyway.
	}

	if ac, ok := c.Auths[key]; ok {
		return toAuthConfig(ac), true, nil
	}
	// Legacy fallback: keys may be stored as URLs ("https://gcr.io/v1/")
	// while we look up bare hostnames.
	host := convertToHostname(key)
	for k, ac := range c.Auths {
		if convertToHostname(k) == host {
			return toAuthConfig(ac), true, nil
		}
	}
	return AuthConfig{}, false, nil
}

func (c *dockerConfig) helperFor(key string) string {
	if h, ok := c.CredHelpers[key]; ok {
		return h
	}
	return c.CredsStore
}

// runCredentialHelper executes `docker-credential-<helper> get` with key on
// stdin and parses the JSON response. Returns (cfg, true, nil) on success,
// (zero, false, nil) when the helper reports "not found", and an error
// otherwise.
func runCredentialHelper(helper, key string) (AuthConfig, bool, error) {
	cmd := exec.Command("docker-credential-"+helper, "get")
	cmd.Stdin = strings.NewReader(key)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		out := strings.TrimSpace(stdout.String() + stderr.String())
		if isCredsNotFound(out) {
			return AuthConfig{}, false, nil
		}
		return AuthConfig{}, false, fmt.Errorf("docker-credential-%s get %q: %w (%s)", helper, key, err, out)
	}
	var resp struct {
		Username string
		Secret   string
	}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return AuthConfig{}, false, fmt.Errorf("decoding docker-credential-%s response: %w", helper, err)
	}
	// docker-credential-helpers signal an identity token by setting Username to "<token>".
	if resp.Username == "<token>" {
		return AuthConfig{IdentityToken: resp.Secret}, true, nil
	}
	return AuthConfig{Username: resp.Username, Password: resp.Secret}, true, nil
}

func isCredsNotFound(msg string) bool {
	// Helpers print this exact string (case-insensitive) when no entry matches.
	// See github.com/docker/docker-credential-helpers/credentials.errCredentialsNotFoundMessage.
	return strings.EqualFold(strings.TrimSpace(msg), "credentials not found in native keychain")
}

func toAuthConfig(a dockerAuth) AuthConfig {
	return AuthConfig{
		Username:      a.Username,
		Password:      a.Password,
		IdentityToken: a.IdentityToken,
		RegistryToken: a.RegistryToken,
	}
}

// decodeAuth decodes a base64("user:pass") string. Mirrors docker/cli.
func decodeAuth(s string) (string, string, error) {
	if s == "" {
		return "", "", nil
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// Some configs use the URL-safe variant.
		decoded, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return "", "", err
		}
	}
	user, pass, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", fmt.Errorf("auth field missing ':' separator")
	}
	return user, strings.Trim(pass, "\x00"), nil
}

// convertToHostname strips an optional scheme + path from a registry key,
// matching the legacy docker/cli helper.
func convertToHostname(s string) string {
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			if u.Port() == "" {
				return u.Hostname()
			}
			return net.JoinHostPort(u.Hostname(), u.Port())
		}
	}
	host, _, _ := strings.Cut(s, "/")
	return host
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
