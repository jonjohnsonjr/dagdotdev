// Adapted from github.com/docker/distribution/registry/client/auth/challenge,
// trimmed to the parsing surface we use (ResponseChallenges + Challenge).
// The Manager / simpleManager / canonicalAddr machinery from upstream is
// dropped since we never wire it up.

package transport

import (
	"net/http"
	"strings"
)

// Challenge carries information from a WWW-Authenticate response header.
// See RFC 2617.
type Challenge struct {
	Scheme     string
	Parameters map[string]string
}

// ResponseChallenges returns the auth challenges advertised on a 401
// response. Other status codes return nil.
func ResponseChallenges(resp *http.Response) []Challenge {
	if resp.StatusCode != http.StatusUnauthorized {
		return nil
	}
	var out []Challenge
	for _, h := range resp.Header[http.CanonicalHeaderKey("WWW-Authenticate")] {
		v, p := parseValueAndParams(h)
		if v != "" {
			out = append(out, Challenge{Scheme: v, Parameters: p})
		}
	}
	return out
}

type octetType byte

const (
	isToken octetType = 1 << iota
	isSpace
)

var octetTypes [256]octetType

func init() {
	for c := 0; c < 256; c++ {
		var t octetType
		isCtl := c <= 31 || c == 127
		isChar := c >= 0 && c <= 127
		isSeparator := strings.ContainsRune(" \t\"(),/:;<=>?@[]\\{}", rune(c))
		if strings.ContainsRune(" \t\r\n", rune(c)) {
			t |= isSpace
		}
		if isChar && !isCtl && !isSeparator {
			t |= isToken
		}
		octetTypes[c] = t
	}
}

func parseValueAndParams(header string) (value string, params map[string]string) {
	params = make(map[string]string)
	value, s := expectToken(header)
	if value == "" {
		return
	}
	value = strings.ToLower(value)
	s = "," + skipSpace(s)
	for strings.HasPrefix(s, ",") {
		var pkey string
		pkey, s = expectToken(skipSpace(s[1:]))
		if pkey == "" {
			return
		}
		if !strings.HasPrefix(s, "=") {
			return
		}
		var pvalue string
		pvalue, s = expectTokenOrQuoted(s[1:])
		if pvalue == "" {
			return
		}
		params[strings.ToLower(pkey)] = pvalue
		s = skipSpace(s)
	}
	return
}

func skipSpace(s string) string {
	i := 0
	for ; i < len(s); i++ {
		if octetTypes[s[i]]&isSpace == 0 {
			break
		}
	}
	return s[i:]
}

func expectToken(s string) (token, rest string) {
	i := 0
	for ; i < len(s); i++ {
		if octetTypes[s[i]]&isToken == 0 {
			break
		}
	}
	return s[:i], s[i:]
}

func expectTokenOrQuoted(s string) (value, rest string) {
	if !strings.HasPrefix(s, "\"") {
		return expectToken(s)
	}
	s = s[1:]
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			return s[:i], s[i+1:]
		case '\\':
			p := make([]byte, len(s)-1)
			j := copy(p, s[:i])
			escape := true
			for i = i + 1; i < len(s); i++ {
				b := s[i]
				switch {
				case escape:
					escape = false
					p[j] = b
					j++
				case b == '\\':
					escape = true
				case b == '"':
					return string(p[:j]), s[i+1:]
				default:
					p[j] = b
					j++
				}
			}
			return "", ""
		}
	}
	return "", ""
}
