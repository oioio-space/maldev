package memory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecureZero(t *testing.T) {
	buf := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x41, 0x42}
	SecureZero(buf)
	for i, b := range buf {
		assert.Equal(t, byte(0), b, "byte at index %d should be zero", i)
	}
}

func TestSecureZero_Empty(t *testing.T) {
	// Should not panic on empty slice.
	SecureZero(nil)
	SecureZero([]byte{})
}

func TestDoSecret(t *testing.T) {
	// Verify f is invoked and observable side-effects happen, independent
	// of whether the build enabled GOEXPERIMENT=runtimesecret.
	called := false
	DoSecret(func() {
		called = true
	})
	assert.True(t, called, "DoSecret must invoke f")
}

func TestDoSecret_NestedAndValue(t *testing.T) {
	// The documented pattern: construct result outside, copy inside.
	var out []byte
	DoSecret(func() {
		tmp := []byte{0x11, 0x22, 0x33}
		out = make([]byte, len(tmp))
		copy(out, tmp)
	})
	assert.Equal(t, []byte{0x11, 0x22, 0x33}, out)
}

func TestSecretEnabled(t *testing.T) {
	// The stub build always reports false. The runtime/secret-backed build
	// reports true only while inside a DoSecret call, false outside.
	outer := SecretEnabled()
	assert.False(t, outer, "SecretEnabled must be false outside DoSecret")

	var inside bool
	DoSecret(func() {
		inside = SecretEnabled()
	})

	// Stub build: always false. Experimental build: true. Either is correct
	// for its respective build, so we only assert the outer-scope invariant.
	_ = inside
}
