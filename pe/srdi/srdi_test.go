package srdi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)
	assert.True(t, cfg.ClearHeader)
	assert.True(t, cfg.ObfuscateImports)
	assert.Empty(t, cfg.FunctionName)
	assert.Empty(t, cfg.Parameter)
}

func TestConvertDLLBytes_InvalidPE(t *testing.T) {
	_, err := ConvertDLLBytes([]byte("not a PE"), nil)
	assert.Error(t, err, "should reject non-PE input")
}

func TestConvertDLLBytes_TooShort(t *testing.T) {
	_, err := ConvertDLLBytes([]byte("M"), nil)
	assert.Error(t, err, "should reject single-byte input")
}

func TestConvertDLLBytes_EmptyInput(t *testing.T) {
	_, err := ConvertDLLBytes(nil, nil)
	assert.Error(t, err, "should reject nil input")
}

func TestConvertDLLBytes_MinimalMZ(t *testing.T) {
	// Minimal valid MZ header — bootstrap will be generated.
	mz := make([]byte, 256)
	mz[0] = 'M'
	mz[1] = 'Z'

	result, err := ConvertDLLBytes(mz, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, result, "should produce shellcode")
	assert.Greater(t, len(result), len(mz), "shellcode should be larger than input (bootstrap prepended)")
}

func TestConvertDLL_MissingFile(t *testing.T) {
	_, err := ConvertDLL("/nonexistent/path/to/file.dll", nil)
	assert.Error(t, err, "should fail on missing file")
}
