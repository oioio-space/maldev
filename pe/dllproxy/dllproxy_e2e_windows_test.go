//go:build windows

package dllproxy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/pe/dllproxy"
	"github.com/oioio-space/maldev/pe/parse"
)

// TestE2E_VersionDllForwarder is the end-to-end proof: emit a proxy
// for version.dll, drop it in a writable directory, LoadLibrary it
// from there, resolve a known export via GetProcAddress, and assert
// the call reaches the legitimate System32!version.dll through the
// GLOBALROOT forwarder.
//
// version.dll is the smallest "interesting" target: 17 exports and
// stable across every Windows version we care about. A failure here
// means the emitted PE layout is rejected by the actual Windows
// loader.
func TestE2E_VersionDllForwarder(t *testing.T) {
	const target = "version.dll"
	system32 := filepath.Join(os.Getenv("SystemRoot"), "System32", target)

	f, err := parse.Open(system32)
	require.NoError(t, err, "open System32!version.dll")
	defer f.Close()

	exports, err := f.Exports()
	require.NoError(t, err)
	require.NotEmpty(t, exports)

	proxy, err := dllproxy.Generate(target, exports, dllproxy.Options{})
	require.NoError(t, err)

	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, target)
	require.NoError(t, os.WriteFile(proxyPath, proxy, 0o644))

	// LoadLibraryW the proxy from its absolute path so we bypass the
	// usual search order and load OUR DLL specifically.
	utf16 := windows.StringToUTF16Ptr(proxyPath)
	mod, err := windows.LoadLibrary(proxyPath)
	require.NoError(t, err, "Windows loader rejected the emitted PE — utf16=%v", utf16)
	defer windows.FreeLibrary(mod)

	// Resolve GetFileVersionInfoSizeA — present in every version.dll
	// since Windows XP.
	const exportName = "GetFileVersionInfoSizeA"
	addr, err := windows.GetProcAddress(mod, exportName)
	require.NoError(t, err, "GetProcAddress failed — forwarder did not resolve")
	assert.NotZero(t, addr, "resolved address must be non-zero")

	// The resolved address MUST point inside the real System32 module,
	// not inside our proxy. That's the entire point of the forwarder:
	// the loader follows the path string and returns the real export.
	realMod, err := windows.LoadLibrary(system32)
	require.NoError(t, err)
	defer windows.FreeLibrary(realMod)
	realAddr, err := windows.GetProcAddress(realMod, exportName)
	require.NoError(t, err)
	assert.Equal(t, realAddr, addr,
		"forwarder did not resolve to the real System32 export")
}
