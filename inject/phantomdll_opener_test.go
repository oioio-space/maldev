//go:build windows

package inject

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/oioio-space/maldev/testutil"
)

// TestPhantomDLLInject_UsesProvidedOpener confirms the new Opener flows
// through the injection path. PID 1 is invalid for OpenProcess so the
// injection fails deep — but only AFTER the opener has been consulted
// twice (once for PE parse, once for the section handle). Both calls
// must target the same System32 DLL path.
func TestPhantomDLLInject_UsesProvidedOpener(t *testing.T) {
	spy := &testutil.SpyOpener{}
	_ = PhantomDLLInject(1, "ntdll.dll", []byte{0x90, 0xC3}, spy)

	// PhantomDLLInject(pid=1, ...) will fail at OpenProcess, but only
	// after doing both opens through the Opener. Expect exactly 2 opens
	// on the same ntdll.dll path.
	assert.Equal(t, int32(2), spy.Calls.Load(),
		"opener must be consulted exactly twice (PE parse + section handle)")
	paths := spy.Paths()
	if len(paths) >= 1 {
		assert.Equal(t, "ntdll.dll", filepath.Base(paths[0]))
	}
	if len(paths) >= 2 {
		assert.Equal(t, paths[0], paths[1],
			"both opens must target the same path")
	}
}
