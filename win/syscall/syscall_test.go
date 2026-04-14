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

func TestHashGateResolver(t *testing.T) {
	r := NewHashGate()

	// NtClose is a simple, always-present NT function.
	ssn, err := r.Resolve("NtClose")
	require.NoError(t, err, "HashGate should resolve NtClose")
	assert.Greater(t, ssn, uint16(0), "NtClose SSN must be > 0")
	t.Logf("HashGate NtClose SSN: %d (0x%04X)", ssn, ssn)

	// Verify HashGate agrees with HellsGate.
	hg := NewHellsGate()
	hellSSN, err := hg.Resolve("NtClose")
	require.NoError(t, err)
	assert.Equal(t, hellSSN, ssn, "HashGate and HellsGate should return the same SSN")
}

func TestHashGateResolver_NotFound(t *testing.T) {
	r := NewHashGate()
	_, err := r.Resolve("NtNonExistentFunction12345")
	assert.Error(t, err, "non-existent function should fail")
}

func TestHashGateChain(t *testing.T) {
	// Verify HashGate composes with Chain.
	c := Chain(NewHashGate(), NewHellsGate())
	ssn, err := c.Resolve("NtClose")
	require.NoError(t, err)
	assert.Greater(t, ssn, uint16(0))
}

func TestCallByHash(t *testing.T) {
	// Use NtQuerySystemInformation(SystemBasicInformation = 0) via hash.
	// This is safe to call and returns basic system info.
	caller := New(MethodWinAPI, nil)

	// hash.ROR13("NtClose") — NtClose takes a single HANDLE argument.
	// Passing an invalid handle (0xDEAD) should return STATUS_INVALID_HANDLE.
	hashNtClose := ror13str("NtClose")
	r, err := caller.CallByHash(hashNtClose, 0xDEAD)
	// We expect a non-zero NTSTATUS (invalid handle) — the point is it didn't panic.
	assert.Error(t, err, "NtClose with invalid handle should return error")
	assert.NotZero(t, r, "NTSTATUS should be non-zero for invalid handle")
}

func TestCallByHash_IndirectSyscall(t *testing.T) {
	caller := New(MethodIndirect, Chain(NewHashGate(), NewHellsGate()))
	hashNtClose := ror13str("NtClose")
	r, err := caller.CallByHash(hashNtClose, 0xDEAD)
	assert.Error(t, err)
	assert.NotZero(t, r)
}

// TestAllResolversAgree verifies that all 4 SSN resolvers return the same
// value for the same function. If they disagree, one of them has a bug.
func TestAllResolversAgree(t *testing.T) {
	type namedResolver struct {
		name string
		r    SSNResolver
	}
	resolvers := []namedResolver{
		{"HellsGate", NewHellsGate()},
		{"HalosGate", NewHalosGate()},
		{"Tartarus", NewTartarus()},
		{"HashGate", NewHashGate()},
	}

	funcs := []string{
		"NtAllocateVirtualMemory",
		"NtProtectVirtualMemory",
		"NtCreateThreadEx",
		"NtClose",
	}

	for _, fn := range funcs {
		var firstSSN uint16
		for i, nr := range resolvers {
			ssn, err := nr.r.Resolve(fn)
			require.NoError(t, err, "%s failed to resolve %s", nr.name, fn)
			if i == 0 {
				firstSSN = ssn
			} else {
				assert.Equal(t, firstSSN, ssn,
					"%s: %s returned 0x%04X but %s returned 0x%04X",
					fn, resolvers[0].name, firstSSN, nr.name, ssn)
			}
		}
		t.Logf("%s SSN=0x%04X (all 4 agree)", fn, firstSSN)
	}
}

func TestNewHellsGate(t *testing.T) {
	r := NewHellsGate()
	require.NotNil(t, r, "NewHellsGate must return a non-nil SSNResolver")

	// Verify it satisfies the SSNResolver interface by resolving a known function.
	ssn, err := r.Resolve("NtClose")
	require.NoError(t, err)
	assert.Greater(t, ssn, uint16(0))
}

func TestNewHalosGate(t *testing.T) {
	r := NewHalosGate()
	require.NotNil(t, r, "NewHalosGate must return a non-nil SSNResolver")

	// Verify it satisfies the SSNResolver interface by resolving a known function.
	ssn, err := r.Resolve("NtClose")
	require.NoError(t, err)
	assert.Greater(t, ssn, uint16(0))
}

func TestNewTartarus(t *testing.T) {
	r := NewTartarus()
	require.NotNil(t, r, "NewTartarus must return a non-nil SSNResolver")

	// Verify it satisfies the SSNResolver interface by resolving a known function.
	ssn, err := r.Resolve("NtClose")
	require.NoError(t, err)
	assert.Greater(t, ssn, uint16(0))
}
