package bridge

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"reflect"
)

// RPC provides typed remote procedure calls over the bridge. Gob
// encoding/decoding is handled internally — callers work with plain
// Go values.
//
// Implant side (Listener):
//
//	rpc := bridge.NewRPC(listener)
//	var result SearchResult
//	rpc.Call("search", "password.txt", &result)
//
// Handler side (Controller):
//
//	rpc := bridge.NewRPC(ctrl)
//	rpc.Handle("search", func(query string) (SearchResult, error) {
//	    return SearchResult{Matches: find(query)}, nil
//	})
type RPC struct {
	listener   *Listener
	controller *Controller
}

// NewRPC wraps a Listener (implant-side) for typed RPC calls.
func NewRPC(l *Listener) *RPC {
	return &RPC{listener: l}
}

// NewRPCHandler wraps a Controller (handler-side) for typed RPC handlers.
func NewRPCHandler(c *Controller) *RPC {
	return &RPC{controller: c}
}

// Call sends a typed RPC command. args is gob-encoded automatically,
// result is gob-decoded from the response. Pass nil for either if unused.
func (r *RPC) Call(name string, args interface{}, result interface{}) error {
	if r.listener == nil {
		return fmt.Errorf("RPC.Call requires a Listener (use NewRPC)")
	}

	var buf bytes.Buffer
	if args != nil {
		if err := gob.NewEncoder(&buf).Encode(args); err != nil {
			return fmt.Errorf("encode args: %w", err)
		}
	}

	resp, err := r.listener.Call(name, buf.Bytes())
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

// Handle registers a typed RPC handler. The handler function must have
// the signature: func(argType) (resultType, error).
// Gob decoding/encoding is handled internally.
//
// Example:
//
//	rpc.Handle("search", func(query string) ([]string, error) {
//	    return findFiles(query), nil
//	})
//
//	rpc.Handle("read_mem", func(addr uint64) ([]byte, error) {
//	    return readMemory(addr), nil
//	})
func (r *RPC) Handle(name string, handler interface{}) {
	if r.controller == nil {
		return
	}
	r.controller.Register(name, makeGobHandler(handler))
}

// makeGobHandler wraps a typed func(T) (R, error) into a CommandHandler
// using reflection. Supports any signature where the arg and return types
// are gob-encodable.
func makeGobHandler(handler interface{}) CommandHandler {
	fn := reflect.ValueOf(handler)
	ft := fn.Type()

	if ft.Kind() != reflect.Func {
		return func(_ []byte) ([]byte, error) {
			return nil, fmt.Errorf("handler must be a func, got %T", handler)
		}
	}

	return func(data []byte) ([]byte, error) {
		var args []reflect.Value

		// Decode input arg if the function takes one.
		if ft.NumIn() == 1 {
			argPtr := reflect.New(ft.In(0))
			if len(data) > 0 {
				if err := gobDecode(data, argPtr.Interface()); err != nil {
					return nil, fmt.Errorf("decode arg: %w", err)
				}
			}
			args = append(args, argPtr.Elem())
		}

		results := fn.Call(args)

		// Last return must be error.
		if len(results) >= 2 {
			if errVal := results[len(results)-1]; !errVal.IsNil() {
				return nil, errVal.Interface().(error)
			}
		}

		// First return is the result value.
		if len(results) >= 1 {
			result := results[0].Interface()
			if result == nil {
				return nil, nil
			}
			return gobEncode(result)
		}

		return nil, nil
	}
}

func gobEncode(v interface{}) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return nil, fmt.Errorf("gob encode: %w", err)
	}
	return buf.Bytes(), nil
}

func gobDecode(data []byte, v interface{}) error {
	return gob.NewDecoder(bytes.NewReader(data)).Decode(v)
}
