package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpyOpener_RecordsCallsAndDelegates(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	require.NoError(t, os.WriteFile(a, []byte("aa"), 0o600))
	require.NoError(t, os.WriteFile(b, []byte("bb"), 0o600))

	spy := &SpyOpener{}

	fa, err := spy.Open(a)
	require.NoError(t, err)
	fa.Close()

	fb, err := spy.Open(b)
	require.NoError(t, err)
	fb.Close()

	assert.Equal(t, int32(2), spy.Calls.Load())
	assert.Equal(t, []string{a, b}, spy.Paths())
	assert.Equal(t, b, spy.Last())
}

func TestSpyOpener_EmptyLast(t *testing.T) {
	spy := &SpyOpener{}
	assert.Equal(t, "", spy.Last())
	assert.Empty(t, spy.Paths())
}
