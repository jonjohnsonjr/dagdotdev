package apk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/jonjohnsonjr/dagdotdev/internal/explore/lexer"
)

func evalBytes(j string, b []byte) ([]byte, string, error) {
	quote := false // this is a hack, we should be lexing properly instead
	l := lexer.Lex(j, j)
	item := l.NextItem()

	// Test the first thing to see if it's expected to be JSON.
	var v interface{} = b
	if item.Typ == lexer.ItemAccessor || item.Typ == lexer.ItemIndex {
		if err := json.Unmarshal(json.RawMessage(b), &v); err != nil {
			return nil, "", fmt.Errorf("unmarshal: %w", err)
		}
	}

	for {
		if item.Typ == lexer.ItemEOF {
			break
		}
		switch item.Typ {
		case lexer.ItemError:
			return nil, "", fmt.Errorf("lexer.ItemError: %s", item.Val)
		case lexer.ItemAccessor:
			quote = true
			vv, ok := v.(map[string]interface{})
			if !ok {
				return nil, "", fmt.Errorf("eval: access %s", item.Val)
			}
			v = vv[item.Val]
		case lexer.ItemIndex:
			vv, ok := v.([]interface{})
			if !ok {
				return nil, "", fmt.Errorf("eval: index %s", item.Val)
			}
			idx, err := strconv.Atoi(item.Val)
			if err != nil {
				return nil, "", fmt.Errorf("atoi: %w", err)
			}
			v = vv[idx]
		case lexer.ItemSentinel:
			val := strings.TrimSpace(item.Val)
			if val == "base64 -d" {
				s, err := toString(v)
				if err != nil {
					return nil, "", err
				}

				v, err = base64.StdEncoding.DecodeString(s)
				if err != nil {
					return nil, "", fmt.Errorf("base64 -d: %w", err)
				}
			} else if val == `awk '{print $1"="}'` {
				s, err := toString(v)
				if err != nil {
					return nil, "", err
				}
				v = s + "="
			} else if val == `awk '{print $1"=="}'` {
				s, err := toString(v)
				if err != nil {
					return nil, "", err
				}
				v = s + "=="
			}
		}
		item = l.NextItem()
	}

	b, err := toBytes(v)
	if err != nil {
		return nil, "", err
	}

	if quote {
		j = "jq -r '" + j + "'"
	}

	return b, j, nil
}

func toString(v interface{}) (string, error) {
	switch vv := v.(type) {
	case string:
		return vv, nil
	case []byte:
		return string(vv), nil
	}
	return "", fmt.Errorf("cannot convert %T to string", v)
}

func toBytes(v interface{}) ([]byte, error) {
	switch vv := v.(type) {
	case string:
		return []byte(vv), nil
	case []byte:
		return vv, nil
	}
	return nil, fmt.Errorf("cannot convert %T to bytes", v)
}
