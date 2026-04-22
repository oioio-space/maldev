package cet

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarker(t *testing.T) {
	assert.Equal(t, []byte{0xF3, 0x0F, 0x1E, 0xFA}, Marker,
		"Marker must match the ENDBR64 opcode")
}

func TestWrapIdempotent(t *testing.T) {
	sc := []byte{0xC3}
	once := Wrap(sc)
	twice := Wrap(once)
	assert.Equal(t, once, twice, "Wrap must be idempotent")
	assert.Equal(t, byte(0xF3), once[0])
	assert.Equal(t, byte(0xC3), once[4], "original byte must follow marker")
}

func TestWrapEmpty(t *testing.T) {
	out := Wrap(nil)
	assert.Equal(t, Marker, out)
}

func TestWrapAlreadyCompliant(t *testing.T) {
	sc := []byte{0xF3, 0x0F, 0x1E, 0xFA, 0x90, 0xC3}
	out := Wrap(sc)
	// Not reallocated, same content.
	assert.Equal(t, sc, out)
}

// TestEnforcedNonWindowsStub asserts the stub reports no enforcement on
// non-Windows so callers can safely branch on Enforced() without a GOOS check.
func TestEnforcedNonWindowsStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows the real implementation queries the current process;
		// skipping here keeps the test meaningful on the stub platform only.
		t.Skip("stub-only test; Windows has a separate implementation")
	}
	if Enforced() {
		t.Errorf("Enforced() on non-Windows stub must be false, got true")
	}
}

// TestDisableNonWindowsStub asserts Disable returns an error on non-Windows.
// Documenting this via a test makes the stub's intentional no-op explicit.
func TestDisableNonWindowsStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stub-only test; Windows has a separate implementation")
	}
	if err := Disable(); err == nil {
		t.Error("Disable() on non-Windows stub must return an error, got nil")
	}
}
