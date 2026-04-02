package inject

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadShellcode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shellcode.bin")

	want := []byte{0x90, 0x90, 0xCC, 0xC3}
	require.NoError(t, os.WriteFile(path, want, 0600))

	got, err := ReadShellcode(path)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestReadShellcodeNotFound(t *testing.T) {
	_, err := ReadShellcode("/nonexistent/path/to/shellcode.bin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shellcode")
}

func TestValidateShellcodeValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "valid.bin")

	// 4 binary bytes: clearly not empty, well below all size limits.
	require.NoError(t, os.WriteFile(path, []byte{0x90, 0x90, 0xCC, 0xC3}, 0600))

	result, err := ValidateShellcode(path)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid, "4-byte binary file should pass validation; errors: %v", result.Errors)
	assert.Equal(t, 4, result.Size)
}

func TestValidateShellcodeEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.bin")

	require.NoError(t, os.WriteFile(path, []byte{}, 0600))

	result, err := ValidateShellcode(path)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Valid, "empty file should fail validation")
	assert.NotEmpty(t, result.Errors)
}
