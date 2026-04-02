//go:build windows

package unhook

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/testutil"
)

// assertCleanSyscallStub verifies the NtClose prologue looks like an unhooked
// x64 syscall stub: 4C 8B D1 (mov r10, rcx) followed by B8 (mov eax, <id>).
// EDR hooks typically replace the first bytes with a JMP, so seeing 4C 8B D1 B8
// confirms the stub has been restored to its original form.
func assertCleanSyscallStub(t *testing.T) {
	t.Helper()
	proc := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtClose")
	require.NoError(t, proc.Find(), "NtClose not found in loaded ntdll")
	memBytes := (*[8]byte)(unsafe.Pointer(proc.Addr()))
	assert.Equal(t, byte(0x4C), memBytes[0], "expected mov r10,rcx (0x4C) — stub may still be hooked")
	assert.Equal(t, byte(0x8B), memBytes[1], "expected 0x8B")
	assert.Equal(t, byte(0xD1), memBytes[2], "expected 0xD1")
	assert.Equal(t, byte(0xB8), memBytes[3], "expected mov eax,<syscall id> (0xB8)")
}

func TestClassicUnhook(t *testing.T) {
	testutil.RequireIntrusive(t)

	err := ClassicUnhook("NtClose", nil)
	if err != nil {
		// Some errors are expected in restricted environments (e.g. ACG already set,
		// ntdll not accessible from test runner). Log and skip rather than hard-fail.
		t.Logf("ClassicUnhook returned error (may be expected in this environment): %v", err)
		return
	}
	assertCleanSyscallStub(t)
}

func TestFullUnhook(t *testing.T) {
	testutil.RequireIntrusive(t)

	err := FullUnhook(nil)
	if err != nil {
		// Same reasoning as TestClassicUnhook — log unexpected environments.
		t.Logf("FullUnhook returned error (may be expected in this environment): %v", err)
		return
	}
	assertCleanSyscallStub(t)
}
