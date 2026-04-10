//go:build windows

package bof

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

// TestLoad_RealBOF loads a real COFF object compiled from C with mingw.
// This BOF imports GetUserNameA — tests parsing of external symbols.
func TestLoad_RealBOF(t *testing.T) {
	data := testutil.LoadPayload(t, "whoami.o")

	b, err := Load(data)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, "go", b.Entry, "BOF entry point must be 'go'")
	t.Logf("loaded BOF: %d bytes, entry=%q", len(data), b.Entry)
}

// TestExecute_RealBOF_Nop executes a minimal BOF that does nothing (no imports).
// Proves the BOF loader can allocate, relocate, and call the entry point.
func TestExecute_RealBOF_Nop(t *testing.T) {
	testutil.RequireIntrusive(t)

	data := testutil.LoadPayload(t, "nop.o")

	b, err := Load(data)
	require.NoError(t, err)

	output, err := b.Execute(nil)
	require.NoError(t, err, "BOF execution must not fail for a no-op BOF")
	t.Logf("BOF output: %q", string(output))
}
