//go:build windows

package api

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestCStringFromPtr_Basic(t *testing.T) {
	src := []byte("hello\x00ignored")
	got := CStringFromPtr(uintptr(unsafe.Pointer(&src[0])), 64)
	assert.Equal(t, "hello", got)
}

func TestCStringFromPtr_NilReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", CStringFromPtr(0, 64))
}

func TestCStringFromPtr_NoTerminatorCappedAtMax(t *testing.T) {
	// 5 bytes, no NUL, max=3 — must return the first 3 and stop.
	src := []byte{'a', 'b', 'c', 'd', 'e'}
	got := CStringFromPtr(uintptr(unsafe.Pointer(&src[0])), 3)
	assert.Equal(t, "abc", got)
}

func TestCStringFromPtr_EmptyString(t *testing.T) {
	// First byte is NUL — empty string.
	src := []byte{0, 'x', 'y'}
	got := CStringFromPtr(uintptr(unsafe.Pointer(&src[0])), 16)
	assert.Equal(t, "", got)
}
