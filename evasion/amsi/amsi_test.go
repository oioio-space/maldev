//go:build windows

package amsi

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/testutil"
)

func TestPatchScanBufferWinAPI(t *testing.T) {
	testutil.RequireIntrusive(t)
	amsiDLL := windows.NewLazySystemDLL("amsi.dll")
	if err := amsiDLL.Load(); err != nil {
		t.Skip("amsi.dll not available")
	}
	proc := amsiDLL.NewProc("AmsiScanBuffer")
	if err := proc.Find(); err != nil {
		t.Skip("AmsiScanBuffer not found")
	}
	addr := proc.Addr()
	err := PatchScanBuffer(nil)
	require.NoError(t, err)
	patched := (*[3]byte)(unsafe.Pointer(addr))
	assert.Equal(t, byte(0x31), patched[0])
	assert.Equal(t, byte(0xC0), patched[1])
	assert.Equal(t, byte(0xC3), patched[2])
}
