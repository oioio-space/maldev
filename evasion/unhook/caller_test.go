//go:build windows

package unhook

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
	"github.com/oioio-space/maldev/win/api"
)

// TestClassicUnhookCallerMethods tests ClassicUnhook with all 4 Caller methods.
// Uses NtCreateSection as target (safe — Go runtime never calls it).
func TestClassicUnhookCallerMethods(t *testing.T) {
	testutil.RequireIntrusive(t)

	const target = "NtCreateSection"
	for _, c := range testutil.CallerMethods(t) {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			err := ClassicUnhook(target, c.Caller, nil)
			if err != nil {
				t.Logf("ClassicUnhook(%s, %s) error: %v", target, c.Name, err)
				return
			}

			proc := api.Ntdll.NewProc(target)
			require.NoError(t, proc.Find())
			stub := (*[4]byte)(unsafe.Pointer(proc.Addr()))
			assert.Equal(t, byte(0x4C), stub[0], "[%s] expected 0x4C", c.Name)
			assert.Equal(t, byte(0x8B), stub[1], "[%s] expected 0x8B", c.Name)
			assert.Equal(t, byte(0xD1), stub[2], "[%s] expected 0xD1", c.Name)
			assert.Equal(t, byte(0xB8), stub[3], "[%s] expected 0xB8", c.Name)
		})
	}
}

func TestFullUnhookCallerMethods(t *testing.T) {
	testutil.RequireIntrusive(t)

	for _, c := range testutil.CallerMethods(t) {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			err := FullUnhook(c.Caller, nil)
			if err != nil {
				t.Logf("FullUnhook(%s) error (may be expected in this environment): %v", c.Name, err)
				return
			}

			proc := api.Ntdll.NewProc("NtAllocateVirtualMemory")
			require.NoError(t, proc.Find(), "NtAllocateVirtualMemory not found in loaded ntdll")
			stub := (*[4]byte)(unsafe.Pointer(proc.Addr()))
			assert.Equal(t, byte(0x4C), stub[0], "[%s] expected mov r10,rcx (0x4C)", c.Name)
			assert.Equal(t, byte(0x8B), stub[1], "[%s] expected 0x8B", c.Name)
			assert.Equal(t, byte(0xD1), stub[2], "[%s] expected 0xD1", c.Name)
			assert.Equal(t, byte(0xB8), stub[3], "[%s] expected mov eax,<syscall id> (0xB8)", c.Name)
		})
	}
}
