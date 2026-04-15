package cet

import (
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
