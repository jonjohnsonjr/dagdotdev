// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package apkversion provides Alpine Linux package version parsing and
// comparison.
//
// Adapted from chainguard.dev/apko/pkg/apk/apk/version.go (Apache 2.0).
// Trimmed to just the ParseVersion + CompareVersions surface we use; the
// constraint matching and dependency resolution machinery is dropped.
//
// See https://github.com/alpinelinux/apk-tools/blob/50ab589e9a5a84592ee4c0ac5a49506bb6c552fc/src/version.c
// for the canonical apk-tools implementation, and
// https://dev.gentoo.org/~ulm/pms/head/pms.html#x1-250003.2 for the comparison
// algorithm.
package apkversion

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var versionRegex = regexp.MustCompile(`^([0-9]+)((\.[0-9]+)*)([a-z]?)((_alpha|_beta|_pre|_rc)([0-9]*))?((_cvs|_svn|_git|_hg|_p)([0-9]*))?((-r)([0-9]+))?$`)

func init() {
	versionRegex.Longest()
}

// preModifier orders pre-release tags so that _alpha < _beta < _pre < _rc <
// (no suffix). Order matters; do not reshuffle.
type preModifier int

const (
	preNone  preModifier = 0
	preAlpha preModifier = 1
	preBeta  preModifier = 2
	prePre   preModifier = 3
	preRC    preModifier = 4
	preMax   preModifier = 1000
)

// postModifier orders post-release tags. Unlike preModifier we don't remap
// "none" to a sentinel max — a missing post-suffix sorts less than any
// present one, which matches apk-tools behavior.
type postModifier int

const (
	postNone postModifier = 0
	postCVS  postModifier = 1
	postSVN  postModifier = 2
	postGit  postModifier = 3
	postHG   postModifier = 4
	postP    postModifier = 5
)

// Version is a parsed Alpine Linux package version.
type Version struct {
	numbers          []int
	letter           rune
	preSuffix        preModifier
	preSuffixNumber  int
	postSuffix       postModifier
	postSuffixNumber int
	revision         int
}

// ParseVersion parses an Alpine package version string.
func ParseVersion(version string) (Version, error) {
	parts := versionRegex.FindAllStringSubmatch(version, -1)
	if len(parts) == 0 {
		return Version{}, fmt.Errorf("invalid version %s, could not parse", version)
	}
	actuals := parts[0]
	if len(actuals) != 14 {
		return Version{}, fmt.Errorf("invalid version %s, could not find enough components", version)
	}

	numbers := make([]int, 0, 10)
	num, err := strconv.Atoi(actuals[1])
	if err != nil {
		return Version{}, fmt.Errorf("invalid version %s, first part is not number: %w", version, err)
	}
	numbers = append(numbers, num)

	if actuals[2] != "" {
		for i, s := range strings.Split(actuals[2], ".") {
			if s == "" {
				continue
			}
			num, err := strconv.Atoi(s)
			if err != nil {
				return Version{}, fmt.Errorf("invalid version %s, part %d is not number: %w", version, i, err)
			}
			numbers = append(numbers, num)
		}
	}

	var letter rune
	if len(actuals[4]) > 0 {
		letter = rune(actuals[4][0])
	}

	pre, err := parsePre(version, actuals[6])
	if err != nil {
		return Version{}, err
	}
	preNum, err := parseSuffixNumber(version, actuals[6], actuals[7])
	if err != nil {
		return Version{}, err
	}

	post, err := parsePost(version, actuals[9])
	if err != nil {
		return Version{}, err
	}
	postNum, err := parseSuffixNumber(version, actuals[9], actuals[10])
	if err != nil {
		return Version{}, err
	}

	var revision int
	if actuals[13] != "" {
		num, err := strconv.Atoi(actuals[13])
		if err != nil {
			return Version{}, fmt.Errorf("invalid version %s, revision %s is not number: %w", version, actuals[13], err)
		}
		revision = num
	}

	return Version{
		numbers:          numbers,
		letter:           letter,
		preSuffix:        pre,
		preSuffixNumber:  preNum,
		postSuffix:       post,
		postSuffixNumber: postNum,
		revision:         revision,
	}, nil
}

func parsePre(version, s string) (preModifier, error) {
	switch s {
	case "_alpha":
		return preAlpha, nil
	case "_beta":
		return preBeta, nil
	case "_pre":
		return prePre, nil
	case "_rc":
		return preRC, nil
	case "":
		return preNone, nil
	}
	return 0, fmt.Errorf("invalid version %s, pre-suffix %s is not valid", version, s)
}

func parsePost(version, s string) (postModifier, error) {
	switch s {
	case "_cvs":
		return postCVS, nil
	case "_svn":
		return postSVN, nil
	case "_git":
		return postGit, nil
	case "_hg":
		return postHG, nil
	case "_p":
		return postP, nil
	case "":
		return postNone, nil
	}
	return 0, fmt.Errorf("invalid version %s, suffix %s is not valid", version, s)
}

func parseSuffixNumber(version, suffix, number string) (int, error) {
	if number == "" {
		return 0, nil
	}
	num, err := strconv.Atoi(number)
	if err != nil {
		return 0, fmt.Errorf("invalid version %s, suffix %s number %s is not number: %w", version, suffix, number, err)
	}
	return num, nil
}

// CompareVersions returns -1, 0, or +1 when a is less than, equal to, or
// greater than b.
func CompareVersions(a, b Version) int {
	for i := 0; i < len(a.numbers) && i < len(b.numbers); i++ {
		if c := cmp(a.numbers[i], b.numbers[i]); c != 0 {
			return c
		}
	}
	if c := cmp(len(a.numbers), len(b.numbers)); c != 0 {
		return c
	}
	if c := cmp(int(a.letter), int(b.letter)); c != 0 {
		return c
	}

	// preNone outranks all other pre-suffixes (no pre-release > any pre-release).
	aPre, bPre := a.preSuffix, b.preSuffix
	if aPre == preNone {
		aPre = preMax
	}
	if bPre == preNone {
		bPre = preMax
	}
	if c := cmp(int(aPre), int(bPre)); c != 0 {
		return c
	}
	if c := cmp(a.preSuffixNumber, b.preSuffixNumber); c != 0 {
		return c
	}

	// post-suffixes do NOT get the None→Max remap; missing < present.
	if c := cmp(int(a.postSuffix), int(b.postSuffix)); c != 0 {
		return c
	}
	if c := cmp(a.postSuffixNumber, b.postSuffixNumber); c != 0 {
		return c
	}
	return cmp(a.revision, b.revision)
}

func cmp(a, b int) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	}
	return 0
}
