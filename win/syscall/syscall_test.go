//go:build windows

package syscall

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCaller(t *testing.T) {
	c := New(MethodWinAPI, nil)
	require.NotNil(t, c)
	assert.Equal(t, MethodWinAPI, c.method)
}

// TestCallerWinAPICall exercises the WinAPI path by calling
// NtQuerySystemInformation with a zero-length buffer. The NT kernel returns
// STATUS_INFO_LENGTH_MISMATCH (0xC0000004) because the buffer is too small,
// which proves the call reached the kernel and the WinAPI path is functional.
func TestCallerWinAPICall(t *testing.T) {
	const statusInfoLengthMismatch uintptr = 0xC0000004

	c := New(MethodWinAPI, nil)
	require.NotNil(t, c)

	// SystemBasicInformation = 0; buffer nil/zero → kernel returns MISMATCH.
	var needed uint32
	r, err := c.Call("NtQuerySystemInformation",
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)
	// The call is expected to fail with STATUS_INFO_LENGTH_MISMATCH.
	require.Error(t, err, "expected an NTSTATUS error when buffer is zero")
	assert.Equal(t, statusInfoLengthMismatch, r,
		"expected STATUS_INFO_LENGTH_MISMATCH (0xC0000004), got 0x%08X", uint32(r))
}

// TestChainResolver verifies that a chained Hell's Gate + Halo's Gate resolver
// can successfully resolve NtClose and return an SSN greater than zero.
func TestChainResolver(t *testing.T) {
	resolver := Chain(NewHellsGate(), NewHalosGate())
	require.NotNil(t, resolver)

	ssn, err := resolver.Resolve("NtClose")
	require.NoError(t, err, "Chain resolver should resolve NtClose without error")
	assert.Greater(t, ssn, uint16(0), "SSN for NtClose must be > 0")
	t.Logf("NtClose SSN: %d (0x%04X)", ssn, ssn)
}

func TestMethodString(t *testing.T) {
	assert.Equal(t, "WinAPI", MethodWinAPI.String())
	assert.Equal(t, "NativeAPI", MethodNativeAPI.String())
	assert.Equal(t, "Direct", MethodDirect.String())
	assert.Equal(t, "Indirect", MethodIndirect.String())
}
