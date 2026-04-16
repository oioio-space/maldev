package bridge

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

// CallGob sends a typed RPC command, encoding args with gob and decoding
// the response into result. Both sides must use matching types.
func (l *Listener) CallGob(name string, args interface{}, result interface{}) error {
	var buf bytes.Buffer
	if args != nil {
		if err := gob.NewEncoder(&buf).Encode(args); err != nil {
			return fmt.Errorf("encode args: %w", err)
		}
	}

	resp, err := l.Call(name, buf.Bytes())
	if err != nil {
		return err
	}

	if result != nil && len(resp) > 0 {
		if err := gob.NewDecoder(bytes.NewReader(resp)).Decode(result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// RegisterGob registers a typed RPC handler that decodes args and encodes
// the response with gob. The handler receives a decoder for the request
// and returns a value to encode as the response.
//
// Example:
//
//	ctrl.RegisterGob("search", func(dec *gob.Decoder) (interface{}, error) {
//	    var query string
//	    dec.Decode(&query)
//	    results := doSearch(query)
//	    return results, nil
//	})
func (c *Controller) RegisterGob(name string, handler func(dec *gob.Decoder) (interface{}, error)) {
	c.Register(name, func(data []byte) ([]byte, error) {
		dec := gob.NewDecoder(bytes.NewReader(data))
		result, err := handler(dec)
		if err != nil {
			return nil, err
		}
		if result == nil {
			return nil, nil
		}
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(result); err != nil {
			return nil, fmt.Errorf("encode response: %w", err)
		}
		return buf.Bytes(), nil
	})
}
