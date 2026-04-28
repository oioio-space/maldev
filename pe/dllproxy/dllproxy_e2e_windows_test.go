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

// TestE2E_Phase2_PayloadLoaded is the Phase 2 proof: emit a proxy whose
// DllMain LoadLibraryA's a sentinel system DLL, LoadLibrary the proxy,
// then assert the payload was actually loaded into the test process.
//
// Sentinel choice: `winmm.dll` — present in every Windows since XP, not
// pulled in by the Go test runner's default imports, and side-effect-
// free to load. Before the test runs we sanity-check it is not already
// in the address space; after the proxy load we expect a non-NULL
// module handle.
func TestE2E_Phase2_PayloadLoaded(t *testing.T) {
	const (
		target  = "version.dll"
		payload = "winmm.dll"
	)

	if isModuleLoaded(payload) {
		t.Skipf("%s already loaded — cannot prove Phase 2 caused the load", payload)
	}

	system32 := filepath.Join(os.Getenv("SystemRoot"), "System32", target)
	f, err := parse.Open(system32)
	require.NoError(t, err)
	defer f.Close()
	exports, err := f.Exports()
	require.NoError(t, err)

	proxy, err := dllproxy.Generate(target, exports, dllproxy.Options{PayloadDLL: payload})
	require.NoError(t, err)

	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, target)
	require.NoError(t, os.WriteFile(proxyPath, proxy, 0o644))

	mod, err := windows.LoadLibrary(proxyPath)
	require.NoError(t, err, "Windows loader rejected the Phase 2 PE")
	defer windows.FreeLibrary(mod)

	require.True(t, isModuleLoaded(payload),
		"GetModuleHandle(%q) returned NULL — payload was not loaded by DllMain", payload)
}

// isModuleLoaded reports whether `name` is currently in the test
// process's module list, without taking a reference (FLAGS=0). Wraps
// kernel32!GetModuleHandleExW because x/sys/windows in our pinned Go
// 1.21 baseline doesn't ship a string-flavoured GetModuleHandle.
func isModuleLoaded(name string) bool {
	var h windows.Handle
	err := windows.GetModuleHandleEx(0, windows.StringToUTF16Ptr(name), &h)
	return err == nil && h != 0
}
