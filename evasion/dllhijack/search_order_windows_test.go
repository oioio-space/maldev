//go:build windows

package dllhijack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchOrder_HasSystem32(t *testing.T) {
	dirs := SearchOrder(`C:\Services\Foo`)
	require.NotEmpty(t, dirs)
	assert.Equal(t, `C:\Services\Foo`, dirs[0], "first entry must be the app dir")

	found := false
	for _, d := range dirs {
		if strings.EqualFold(filepath.Base(d), "System32") {
			found = true
			break
		}
	}
	assert.True(t, found, "System32 must appear somewhere in the search order: %v", dirs)
}

func TestHijackPath_SystemDLLInSystem32(t *testing.T) {
	// kernel32.dll is always in System32; it's a KnownDLL so HijackPath
	// must return zero values regardless of the exe's app dir.
	hi, _ := HijackPath(`C:\NoSuch`, "kernel32.dll")
	assert.Empty(t, hi, "kernel32.dll is a KnownDLL — no hijack opportunity")
}

func TestHijackPath_WritableAppDirHijacks(t *testing.T) {
	// Simulate an app in a writable directory (t.TempDir) importing a
	// DLL that lives only in System32. Expected: TempDir is earlier in
	// the search order AND writable, so HijackPath points there.
	// We pick `winhttp.dll` — present in System32, NOT a KnownDLL (only
	// a small whitelist is, and winhttp isn't on it).
	if isKnownDLL("winhttp.dll") {
		t.Skip("winhttp.dll is a KnownDLL on this host — pick a different sentinel")
	}
	tmp := t.TempDir()

	hi, resolved := HijackPath(tmp, "winhttp.dll")
	assert.Equal(t, tmp, hi, "writable TempDir should be the hijack path")
	assert.NotEmpty(t, resolved, "resolved path should be System32")
	assert.Contains(t, strings.ToLower(resolved), "system32")
}

func TestHijackPath_DLLAlreadyInAppDir(t *testing.T) {
	// If the DLL already exists in the app dir, the loader finds it
	// there FIRST — no hijack possible because the target is already
	// what's being loaded.
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "decoy.dll"), []byte{0}, 0o644))

	hi, resolved := HijackPath(tmp, "decoy.dll")
	assert.Empty(t, hi, "DLL already in app dir — loader finds it there, no earlier hijack opportunity")
	assert.Equal(t, tmp, resolved)
}

func TestIsKnownDLL_Kernel32(t *testing.T) {
	assert.True(t, isKnownDLL("kernel32.dll"))
	assert.True(t, isKnownDLL("KERNEL32.DLL"), "match should be case-insensitive")
	assert.False(t, isKnownDLL("this-is-definitely-not-a-known-dll.dll"))
}
