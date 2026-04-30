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

import "fmt"

// Reference is the interface that consumers use when they can take either a
// tag or a digest.
type Reference interface {
	fmt.Stringer

	Context() Repository
	Identifier() string
	Name() string
	Scope(string) string
}

// ParseReference parses s as either a tagged or digested reference.
func ParseReference(s string, opts ...Option) (Reference, error) {
	if d, err := NewDigest(s, opts...); err == nil {
		return d, nil
	}
	if t, err := NewTag(s, opts...); err == nil {
		return t, nil
	}
	return nil, newErrBadName("could not parse reference: " + s)
}

type stringConst string

// MustParseReference behaves like ParseReference but panics on error. It only
// accepts string constants to discourage runtime use.
func MustParseReference(s stringConst, opts ...Option) Reference {
	ref, err := ParseReference(string(s), opts...)
	if err != nil {
		panic(err)
	}
	return ref
}
