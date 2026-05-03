package crypto

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWipe(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	Wipe(buf)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0}, buf)
}

func TestWipe_Empty(t *testing.T) {
	// Must not panic on nil or zero-length input.
	Wipe(nil)
	Wipe([]byte{})
}

func TestUseDecrypted_HappyPath(t *testing.T) {
	want := []byte("plaintext")
	called := false
	err := UseDecrypted(
		func() ([]byte, error) { return append([]byte(nil), want...), nil },
		func(pt []byte) error {
			called = true
			assert.True(t, bytes.Equal(pt, want))
			return nil
		},
	)
	require.NoError(t, err)
	assert.True(t, called, "fn must be invoked when decrypt succeeds")
}

func TestUseDecrypted_DecryptError(t *testing.T) {
	called := false
	wantErr := errors.New("decrypt failed")
	err := UseDecrypted(
		func() ([]byte, error) { return nil, wantErr },
		func(pt []byte) error {
			called = true
			return nil
		},
	)
	require.ErrorIs(t, err, wantErr)
	assert.False(t, called, "fn must not be invoked when decrypt fails")
}

func TestUseDecrypted_FnErrorStillWipes(t *testing.T) {
	plaintext := []byte("secret-bytes")
	var captured []byte
	wantErr := errors.New("inject failed")
	err := UseDecrypted(
		func() ([]byte, error) { return append([]byte(nil), plaintext...), nil },
		func(pt []byte) error {
			captured = pt // hold the underlying slice
			return wantErr
		},
	)
	require.ErrorIs(t, err, wantErr)
	require.NotNil(t, captured)
	for i, b := range captured {
		assert.Equal(t, byte(0), b, "byte %d must be zero after UseDecrypted returns", i)
	}
}

func TestUseDecrypted_WipeRunsAfterReturn(t *testing.T) {
	plaintext := []byte("expose-me")
	var captured []byte
	err := UseDecrypted(
		func() ([]byte, error) { return append([]byte(nil), plaintext...), nil },
		func(pt []byte) error {
			captured = pt
			// Plaintext is still readable here — wipe runs after fn returns.
			assert.True(t, bytes.Equal(pt, plaintext))
			return nil
		},
	)
	require.NoError(t, err)
	for _, b := range captured {
		assert.Equal(t, byte(0), b)
	}
}
