//go:build !windows

package goldenticket

import (
	"errors"
	"testing"
)

func TestSubmit_NonWindows_ReturnsErrPlatformUnsupported(t *testing.T) {
	err := Submit([]byte{0x01, 0x02, 0x03})
	if !errors.Is(err, ErrPlatformUnsupported) {
		t.Fatalf("Submit on non-Windows: err = %v, want ErrPlatformUnsupported", err)
	}
}
