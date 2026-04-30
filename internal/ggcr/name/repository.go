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
	"fmt"
	"strings"
)

const (
	defaultNamespace = "library"
	repositoryChars  = "abcdefghijklmnopqrstuvwxyz0123456789_-./"
	regRepoDelimiter = "/"
)

// Repository stores a repository name in a structured form.
type Repository struct {
	Registry
	repository string
	original   string
}

func hasImplicitNamespace(repo string, reg Registry) bool {
	return !strings.ContainsRune(repo, '/') && reg.RegistryStr() == DefaultRegistry
}

func (r Repository) RepositoryStr() string {
	if hasImplicitNamespace(r.repository, r.Registry) {
		return fmt.Sprintf("%s/%s", defaultNamespace, r.repository)
	}
	return r.repository
}

func (r Repository) Name() string {
	regName := r.Registry.Name()
	if regName != "" {
		return regName + regRepoDelimiter + r.RepositoryStr()
	}
	return r.RepositoryStr()
}

func (r Repository) String() string { return r.original }

// Scope returns the scope required to perform the given action.
func (r Repository) Scope(action string) string {
	return fmt.Sprintf("repository:%s:%s", r.RepositoryStr(), action)
}

func checkRepository(repository string) error {
	return checkElement("repository", repository, repositoryChars, 2, 255)
}

// NewRepository returns a Repository for the given name.
func NewRepository(name string, opts ...Option) (Repository, error) {
	if len(name) == 0 {
		return Repository{}, newErrBadName("a repository name must be specified")
	}

	// Bare hostnames (no path) are interpreted as a registry-only reference.
	if strings.Count(name, ".") > 0 && !strings.Contains(name, "/") && name != "rocket.chat" {
		return Repository{
			Registry:   Registry{registry: name},
			repository: "",
			original:   name,
		}, nil
	}

	var registry string
	repo := name
	parts := strings.SplitN(name, regRepoDelimiter, 2)
	if len(parts) == 2 && (strings.ContainsRune(parts[0], '.') || strings.ContainsRune(parts[0], ':')) {
		registry = parts[0]
		repo = parts[1]
	}

	if err := checkRepository(repo); err != nil {
		return Repository{}, err
	}

	reg, err := NewRegistry(registry, opts...)
	if err != nil {
		return Repository{}, err
	}
	return Repository{
		Registry:   reg,
		repository: repo,
		original:   name,
	}, nil
}

// Tag returns a Tag in this Repository.
func (r Repository) Tag(identifier string) Tag {
	t := Tag{tag: identifier, Repository: r}
	t.original = t.Name()
	return t
}

// Digest returns a Digest in this Repository.
func (r Repository) Digest(identifier string) Digest {
	d := Digest{digest: identifier, Repository: r}
	d.original = d.Name()
	return d
}
