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

import "strings"

const digestDelim = "@"

// Digest stores a digest reference in a structured form.
type Digest struct {
	Repository
	digest   string
	original string
}

var _ Reference = (*Digest)(nil)

func (d Digest) Context() Repository { return d.Repository }
func (d Digest) Identifier() string  { return d.DigestStr() }
func (d Digest) DigestStr() string   { return d.digest }
func (d Digest) Name() string        { return d.Repository.Name() + digestDelim + d.DigestStr() }
func (d Digest) String() string      { return d.original }

// NewDigest parses a name@digest string.
func NewDigest(name string, opts ...Option) (Digest, error) {
	parts := strings.Split(name, digestDelim)
	if len(parts) != 2 {
		return Digest{}, newErrBadName("a digest must contain exactly one '@' separator (e.g. registry/repository@digest) saw: %s", name)
	}
	base := parts[0]
	dig := parts[1]

	switch {
	case strings.HasPrefix(dig, "sha256:"):
		if err := validateHex(strings.TrimPrefix(dig, "sha256:"), 64); err != nil {
			return Digest{}, err
		}
	case strings.HasPrefix(dig, "sha512:"):
		if err := validateHex(strings.TrimPrefix(dig, "sha512:"), 128); err != nil {
			return Digest{}, err
		}
	default:
		return Digest{}, newErrBadName("unsupported digest algorithm: %s", dig)
	}

	tag, err := NewTag(base, opts...)
	if err == nil {
		base = tag.Repository.String()
	}

	repo, err := NewRepository(base, opts...)
	if err != nil {
		return Digest{}, err
	}
	return Digest{
		Repository: repo,
		digest:     dig,
		original:   name,
	}, nil
}
