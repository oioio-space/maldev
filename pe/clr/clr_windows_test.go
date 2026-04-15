//go:build windows

package clr

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadOrSkip returns a started Runtime, or calls t.Skip if the host does
// not support ICorRuntimeHost legacy COM hosting (no .NET 3.5 installed).
func loadOrSkip(t *testing.T) *Runtime {
	t.Helper()
	rt, err := Load(nil)
	if errors.Is(err, ErrLegacyRuntimeUnavailable) {
		t.Skip("ICorRuntimeHost unavailable on this host (install .NET 3.5)")
	}
	require.NoError(t, err)
	require.NotNil(t, rt)
	return rt
}

func TestInstalledRuntimes(t *testing.T) {
	runtimes, err := InstalledRuntimes()
	require.NoError(t, err)
	require.NotEmpty(t, runtimes, "expected at least one .NET runtime installed")
	for _, r := range runtimes {
		t.Logf("runtime: %s", r)
	}
}

func TestLoadAndClose(t *testing.T) {
	rt := loadOrSkip(t)
	rt.Close()
	// Double-close must be safe.
	rt.Close()
}

func TestExecuteAssemblyEmpty(t *testing.T) {
	rt := loadOrSkip(t)
	defer rt.Close()

	err := rt.ExecuteAssembly(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestExecuteDLLValidation(t *testing.T) {
	rt := loadOrSkip(t)
	defer rt.Close()

	tests := []struct {
		name       string
		dll        []byte
		typeName   string
		methodName string
		arg        string
	}{
		{"empty dll", nil, "T", "M", ""},
		{"missing type", []byte{0x4D, 0x5A}, "", "M", ""},
		{"missing method", []byte{0x4D, 0x5A}, "T", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rt.ExecuteDLL(tt.dll, tt.typeName, tt.methodName, tt.arg)
			assert.Error(t, err)
		})
	}
}
