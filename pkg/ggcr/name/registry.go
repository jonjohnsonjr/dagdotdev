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

package name

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	reLocal        = regexp.MustCompile(`.*\.local(?:host)?(?::\d{1,5})?$`)
	reLoopback     = regexp.MustCompile(regexp.QuoteMeta("127.0.0.1"))
	reipv6Loopback = regexp.MustCompile(regexp.QuoteMeta("::1"))
)

// Registry stores a registry name in a structured form.
type Registry struct {
	registry string
}

func (r Registry) RegistryStr() string { return r.registry }
func (r Registry) Name() string        { return r.RegistryStr() }
func (r Registry) String() string      { return r.Name() }

// Scope returns the scope required to access the registry.
func (r Registry) Scope(string) string {
	return "registry:catalog:*"
}

func (r Registry) isRFC1918() bool {
	ipStr := strings.Split(r.Name(), ":")[0]
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// Scheme returns "http" for endpoints that look local (RFC1918 ranges,
// localhost, .local hostnames, ::1) and "https" for everything else.
func (r Registry) Scheme() string {
	host := r.Name()
	if r.isRFC1918() ||
		strings.HasPrefix(host, "localhost:") ||
		reLocal.MatchString(host) ||
		reLoopback.MatchString(host) ||
		reipv6Loopback.MatchString(host) {
		return "http"
	}
	return "https"
}

func checkRegistry(name string) error {
	if u, err := url.Parse("//" + name); err != nil || u.Host != name {
		return newErrBadName("registries must be valid RFC 3986 URI authorities: %s", name)
	}
	return nil
}

// NewRegistry returns a Registry based on the given name.
func NewRegistry(name string, opts ...Option) (Registry, error) {
	opt := makeOptions(opts...)
	if err := checkRegistry(name); err != nil {
		return Registry{}, err
	}

	if name == "" {
		name = opt.defaultRegistry
	}
	if name == defaultRegistryAlias {
		name = DefaultRegistry
	}

	return Registry{registry: name}, nil
}

