//go:build windows

package etw

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
	"github.com/oioio-space/maldev/win/api"
)

func TestPatch(t *testing.T) {
	testutil.RequireIntrusive(t)

	// Resolve all 5 ETW functions before patching.
	names := []string{
		"EtwEventWrite",
		"EtwEventWriteEx",
		"EtwEventWriteFull",
		"EtwEventWriteString",
		"EtwEventWriteTransfer",
	}
	addrs := make(map[string]uintptr)
	for _, name := range names {
		proc := api.Ntdll.NewProc(name)
		if err := proc.Find(); err != nil {
			t.Logf("%s not present on this OS — skipping", name)
			continue
		}
		addrs[name] = proc.Addr()
	}
	require.NotEmpty(t, addrs, "at least one ETW function must be resolvable")

	err := Patch(nil)
	require.NoError(t, err)

	// Verify each resolved function was patched with 48 33 C0 C3.
	for name, addr := range addrs {
		patched := (*[4]byte)(unsafe.Pointer(addr))
		assert.Equal(t, byte(0x48), patched[0], "%s[0] should be 0x48 (REX.W)", name)
		assert.Equal(t, byte(0x33), patched[1], "%s[1] should be 0x33 (XOR)", name)
		assert.Equal(t, byte(0xC0), patched[2], "%s[2] should be 0xC0 (RAX,RAX)", name)
		assert.Equal(t, byte(0xC3), patched[3], "%s[3] should be 0xC3 (RET)", name)
	}
}

func TestPatchNtTraceEvent(t *testing.T) {
	testutil.RequireIntrusive(t)

	proc := api.Ntdll.NewProc("NtTraceEvent")
	if err := proc.Find(); err != nil {
		t.Skip("NtTraceEvent not present")
	}
	addr := proc.Addr()

	require.NoError(t, PatchNtTraceEvent(nil))

	patched := (*[4]byte)(unsafe.Pointer(addr))
	assert.Equal(t, byte(0x48), patched[0])
	assert.Equal(t, byte(0x33), patched[1])
	assert.Equal(t, byte(0xC0), patched[2])
	assert.Equal(t, byte(0xC3), patched[3])
}

func TestPatchAll(t *testing.T) {
	testutil.RequireIntrusive(t)
	require.NoError(t, PatchAll(nil))
}
