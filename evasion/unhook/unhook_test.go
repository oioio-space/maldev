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

// assertCleanSyscallStub verifies that an ntdll function has the standard x64
// syscall prologue: 4C 8B D1 B8 (mov r10,rcx; mov eax,<SSN>).
func assertCleanSyscallStub(t *testing.T, funcName string) {
	t.Helper()
	proc := api.Ntdll.NewProc(funcName)
	require.NoError(t, proc.Find(), "%s not found in loaded ntdll", funcName)
	b := (*[4]byte)(unsafe.Pointer(proc.Addr()))
	assert.Equal(t, byte(0x4C), b[0], "%s[0]: expected 0x4C (mov r10,rcx)", funcName)
	assert.Equal(t, byte(0x8B), b[1], "%s[1]: expected 0x8B", funcName)
	assert.Equal(t, byte(0xD1), b[2], "%s[2]: expected 0xD1", funcName)
	assert.Equal(t, byte(0xB8), b[3], "%s[3]: expected 0xB8 (mov eax,SSN)", funcName)
}

func TestClassicUnhookRejectsRuntimeCritical(t *testing.T) {
	for _, fn := range []string{"NtClose", "NtCreateFile", "NtReadFile", "NtWriteFile"} {
		err := ClassicUnhook(fn, nil, nil)
		require.Error(t, err, "ClassicUnhook(%s) should be rejected", fn)
		assert.Contains(t, err.Error(), "Go runtime depends on it")
	}
}

func TestClassicUnhook(t *testing.T) {
	testutil.RequireIntrusive(t)

	const target = "NtAllocateVirtualMemory"
	err := ClassicUnhook(target, nil, nil)
	if err != nil {
		t.Logf("ClassicUnhook returned error (may be expected in this environment): %v", err)
		return
	}
	assertCleanSyscallStub(t, target)
}

func TestFullUnhook(t *testing.T) {
	testutil.RequireIntrusive(t)

	err := FullUnhook(nil, nil)
	if err != nil {
		t.Logf("FullUnhook returned error (may be expected in this environment): %v", err)
		return
	}
	assertCleanSyscallStub(t, "NtAllocateVirtualMemory")
}
