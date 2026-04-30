package explore

import (
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

func stringify(anything interface{}) (string, error) {
	switch m := anything.(type) {
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(m))
		for k, v := range m {
			if ks, ok := k.(string); ok {
				j, err := jsonify(v)
				if err != nil {
					return "", err
				}
				out[ks] = j
			} else {
				kj, err := stringify(k)
				if err != nil {
					return "", fmt.Errorf("stringify key: %w", err)
				}
				j, err := jsonify(v)
				if err != nil {
					return "", fmt.Errorf("stringify value: %w", err)
				}
				out[string(kj)] = j
			}
		}
		b, err := json.Marshal(out)
		if err != nil {
			return "", fmt.Errorf("marshal out: %w", err)
		}
		return string(b), nil
	default:
		b, err := json.Marshal(m)
		if err != nil {
			return "", fmt.Errorf("marshal m: %w", err)
		}
		return string(b), nil
	}
}

func jsonify(anything interface{}) (interface{}, error) {
	switch m := anything.(type) {
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(m))
		for k, v := range m {
			if ks, ok := k.(string); ok {
				j, err := jsonify(v)
				if err != nil {
					return nil, fmt.Errorf("jsonify map[%q]: %w", ks, err)
				}
				out[ks] = j
			} else {
				kj, err := stringify(k)
				if err != nil {
					return nil, fmt.Errorf("stringify key: %w", err)
				}
				j, err := jsonify(v)
				if err != nil {
					return nil, fmt.Errorf("jsonify value: %w", err)
				}
				out[string(kj)] = j
			}
		}
		return out, nil
	case []interface{}:
		out := make([]interface{}, len(m))
		for i, v := range m {
			j, err := jsonify(v)
			if err != nil {
				return nil, fmt.Errorf("jsonify list value: %w", err)
			}
			out[i] = j
		}
		return out, nil
	case cbor.Tag:
		return jsonify(map[interface{}]interface{}{
			m.Number: m.Content,
		})
	default:
		return anything, nil
	}
}
