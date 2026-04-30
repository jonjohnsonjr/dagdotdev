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

const (
	tagChars = "abcdefghijklmnopqrstuvwxyz0123456789_-.ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	tagDelim = ":"
)

// Tag stores a tag name in a structured form.
type Tag struct {
	Repository
	tag      string
	original string
}

var _ Reference = (*Tag)(nil)

func (t Tag) Context() Repository  { return t.Repository }
func (t Tag) Identifier() string   { return t.TagStr() }
func (t Tag) TagStr() string       { return t.tag }
func (t Tag) Name() string         { return t.Repository.Name() + tagDelim + t.TagStr() }
func (t Tag) String() string       { return t.original }
func (t Tag) Scope(a string) string { return t.Repository.Scope(a) }

func checkTag(name string) error {
	return checkElement("tag", name, tagChars, 1, 128)
}

// NewTag returns a new Tag for the given name.
func NewTag(name string, opts ...Option) (Tag, error) {
	opt := makeOptions(opts...)
	base := name
	tag := ""

	parts := strings.Split(name, tagDelim)
	// If the last segment looks like a tag (no '/'), peel it off.
	if len(parts) > 1 && !strings.Contains(parts[len(parts)-1], regRepoDelimiter) {
		base = strings.Join(parts[:len(parts)-1], tagDelim)
		tag = parts[len(parts)-1]
	}

	if tag != "" {
		if err := checkTag(tag); err != nil {
			return Tag{}, err
		}
	}

	if tag == "" {
		tag = opt.defaultTag
	}

	repo, err := NewRepository(base, opts...)
	if err != nil {
		return Tag{}, err
	}
	return Tag{Repository: repo, tag: tag, original: name}, nil
}
