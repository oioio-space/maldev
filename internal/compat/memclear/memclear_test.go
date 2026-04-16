package memclear

import (
	"testing"
)

func TestClear(t *testing.T) {
	buf := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x41, 0x42}
	Clear(buf)
	for i, b := range buf {
		if b != 0 {
			t.Errorf("byte at index %d = 0x%02X, want 0x00", i, b)
		}
	}
}

func TestClear_Empty(t *testing.T) {
	// Must not panic on nil or zero-length slice.
	Clear(nil)
	Clear([]byte{})
}

func TestClear_Single(t *testing.T) {
	buf := []byte{0xFF}
	Clear(buf)
	if buf[0] != 0 {
		t.Errorf("single-byte buf = 0x%02X, want 0x00", buf[0])
	}
}
