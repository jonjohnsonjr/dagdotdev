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

// Package name defines structured types for representing image references.
//
// Adapted from github.com/google/go-containerregistry/pkg/name; trimmed to
// the subset we use and stripped of third-party dependencies.
package name

const (
	DefaultRegistry      = "index.docker.io"
	defaultRegistryAlias = "docker.io"

	DefaultTag = "latest"
)

type options struct {
	defaultRegistry string
	defaultTag      string
}

func makeOptions(opts ...Option) options {
	opt := options{
		defaultRegistry: DefaultRegistry,
		defaultTag:      DefaultTag,
	}
	for _, o := range opts {
		o(&opt)
	}
	return opt
}

// Option is a functional option for name parsing.
type Option func(*options)
