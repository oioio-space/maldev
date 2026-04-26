//go:build windows

package goldenticket

import (
	"errors"
	"testing"
)

func TestSubmit_RejectsEmptyKirbi(t *testing.T) {
	err := Submit(nil)
	if !errors.Is(err, ErrInvalidParams) {
		t.Fatalf("Submit(nil): err = %v, want ErrInvalidParams", err)
	}
	err = Submit([]byte{})
	if !errors.Is(err, ErrInvalidParams) {
		t.Fatalf("Submit([]byte{}): err = %v, want ErrInvalidParams", err)
	}
}
