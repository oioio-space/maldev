package srdi

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, ArchX64, cfg.Arch)
	assert.Equal(t, ModuleEXE, cfg.Type)
	assert.Equal(t, 3, cfg.Bypass)
}

func TestConvertBytes_InvalidPE(t *testing.T) {
	_, err := ConvertBytes([]byte("not a PE"), nil)
	assert.Error(t, err, "should reject non-PE input")
}

func TestConvertBytes_TooShort(t *testing.T) {
	_, err := ConvertBytes([]byte("M"), nil)
	assert.Error(t, err, "should reject single-byte input")
}

func TestConvertBytes_Nil(t *testing.T) {
	_, err := ConvertBytes(nil, nil)
	assert.Error(t, err, "should reject nil input")
}

func TestConvertFile_MissingFile(t *testing.T) {
	_, err := ConvertFile("/nonexistent/path/to/file.dll", nil)
	assert.Error(t, err, "should fail on missing file")
}

func TestConvertBytes_RealPE(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("go-donut shellcode generation needs a real PE")
	}
	data, err := os.ReadFile(filepath.Join(os.Getenv("WINDIR"), "System32", "cmd.exe"))
	if err != nil {
		t.Skipf("cannot read cmd.exe: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Arch = ArchX64

	result, err := ConvertBytes(data, cfg)
	require.NoError(t, err)
	assert.NotEmpty(t, result, "should produce shellcode")
	assert.Greater(t, len(result), 100, "shellcode should be non-trivial")
	t.Logf("Generated %d bytes of shellcode from %d bytes PE", len(result), len(data))
}

func TestConvertFile_RealPE(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("go-donut needs a real PE")
	}
	cmdPath := filepath.Join(os.Getenv("WINDIR"), "System32", "cmd.exe")

	cfg := DefaultConfig()
	result, err := ConvertFile(cmdPath, cfg)
	require.NoError(t, err)
	assert.NotEmpty(t, result)
	t.Logf("ConvertFile produced %d bytes", len(result))
}

func TestConvertDLLBytes_InvalidPE(t *testing.T) {
	_, err := ConvertDLLBytes([]byte("not a PE"), nil)
	assert.Error(t, err, "should reject non-PE input")
}

func TestModuleTypeConstants(t *testing.T) {
	assert.Equal(t, ModuleType(1), ModuleNetDLL)
	assert.Equal(t, ModuleType(2), ModuleNetEXE)
	assert.Equal(t, ModuleType(3), ModuleDLL)
	assert.Equal(t, ModuleType(4), ModuleEXE)
	assert.Equal(t, ModuleType(5), ModuleVBS)
	assert.Equal(t, ModuleType(6), ModuleJS)
	assert.Equal(t, ModuleType(7), ModuleXSL)
}

func TestArchConstants(t *testing.T) {
	assert.Equal(t, Arch(0), ArchX32)
	assert.Equal(t, Arch(1), ArchX64)
	assert.Equal(t, Arch(2), ArchX84)
}
