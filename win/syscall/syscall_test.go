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
	assert.Equal(t, "IndirectAsm", MethodIndirectAsm.String())
}

// TestMethodIndirectAsm exercises the Go-asm indirect syscall stub end-to-end
// by invoking NtClose with a bogus handle. The kernel must return a non-zero
// NTSTATUS (STATUS_INVALID_HANDLE = 0xC0000008 typically) — proving the call
// reached ring 0 and came back through our gadget without crashing.
func TestMethodIndirectAsm(t *testing.T) {
	c := New(MethodIndirectAsm, Chain(NewHashGate(), NewHellsGate()))
	r, err := c.Call("NtClose", 0xDEAD)
	require.Error(t, err, "NtClose(0xDEAD) should fail")
	assert.NotZero(t, r, "NTSTATUS should be non-zero for invalid handle")
}

// TestMethodIndirectAsm_CallByHash exercises the CallByHash path through the
// asm stub — the binary contains only the uint32 hash, no "NtClose" string.
func TestMethodIndirectAsm_CallByHash(t *testing.T) {
	c := New(MethodIndirectAsm, nil)
	r, err := c.CallByHash(ror13str("NtClose"), 0xDEAD)
	require.Error(t, err)
	assert.NotZero(t, r)
}

// TestPickSyscallGadget_Pool verifies the gadget pool captures more than one
// `syscall;ret` triple in ntdll's .text and that successive picks vary
// (otherwise the random selection is broken).
func TestPickSyscallGadget_Pool(t *testing.T) {
	first, err := pickSyscallGadget()
	require.NoError(t, err)
	require.NotZero(t, first)

	require.Greater(t, len(gadgetPool), 1, "expected multiple gadgets in ntdll .text — pool diversity is the whole point")

	// 16 picks against a pool > 1 should hit at least 2 distinct addresses
	// with overwhelming probability (P(all same) = 1/N^15 → effectively 0).
	seen := map[uintptr]struct{}{first: {}}
	for i := 0; i < 16; i++ {
		g, err := pickSyscallGadget()
		require.NoError(t, err)
		seen[g] = struct{}{}
	}
	assert.Greater(t, len(seen), 1, "16 random picks all returned the same gadget — randomisation broken")
}

// TestNewHashGateWith_CustomHash plugs a non-ROR13 hash (FNV-1a 32-bit) into
// the resolver and asserts the SSN returned matches what HellsGate produces.
// This is the swappable-hash contract: any deterministic [string]→uint32
// function works, as long as both ends agree.
func TestNewHashGateWith_CustomHash(t *testing.T) {
	fnv1a := func(s string) uint32 {
		const offset, prime = uint32(2166136261), uint32(16777619)
		h := offset
		for i := 0; i < len(s); i++ {
			h ^= uint32(s[i])
			h *= prime
		}
		return h
	}

	r := NewHashGateWith(fnv1a)
	ssn, err := r.Resolve("NtClose")
	require.NoError(t, err)
	assert.Greater(t, ssn, uint16(0))

	// Must agree with the canonical Hell's Gate SSN.
	hg := NewHellsGate()
	hellSSN, err := hg.Resolve("NtClose")
	require.NoError(t, err)
	assert.Equal(t, hellSSN, ssn, "custom-hash HashGate must match HellsGate on the resolved SSN")
}

// TestCallerWithHashFunc exercises CallByHash when both ends use a custom
// hash function (here: FNV-1a). If the resolver inside CallByHash did not
// honour Caller.hashFunc, the export-table walk would fail.
func TestCallerWithHashFunc(t *testing.T) {
	fnv1a := func(s string) uint32 {
		const offset, prime = uint32(2166136261), uint32(16777619)
		h := offset
		for i := 0; i < len(s); i++ {
			h ^= uint32(s[i])
			h *= prime
		}
		return h
	}

	c := New(MethodIndirectAsm, nil).WithHashFunc(fnv1a)
	r, err := c.CallByHash(fnv1a("NtClose"), 0xDEAD)
	require.Error(t, err, "NtClose(0xDEAD) should fail")
	assert.NotZero(t, r)
}

// TestNewHashGateWith_ModuleHashIsSwapped guards the end-to-end hash-family
// swap: NewHashGateWith must use the supplied fn to compute the ntdll.dll
// module-name hash, not the precomputed ROR13Module constant. We pass a
// sentinel fn that returns a unique value only for "ntdll.dll" — if the
// resolver still walks the PEB looking for the ROR13Module constant the
// PEB walk fails and Resolve errors out.
func TestNewHashGateWith_ModuleHashIsSwapped(t *testing.T) {
	const sentinel uint32 = 0xCAFEBABE
	sentinelFn := func(s string) uint32 {
		if s == "ntdll.dll" {
			return sentinel
		}
		// Function-name hashes still need to match what pebExportByHashFunc
		// computes, so fall back to ROR13 there.
		return ror13str(s)
	}
	r := NewHashGateWith(sentinelFn)
	require.Equal(t, sentinel, r.ntdllHash, "ntdllHash must come from fn(\"ntdll.dll\")")
	ssn, err := r.Resolve("NtClose")
	require.NoError(t, err, "PEB walk with the sentinel fn must locate ntdll")
	assert.Greater(t, ssn, uint16(0))
}

// TestHashROR13_MatchesPackageDefault verifies the exported HashROR13 var is
// the same algorithm the package uses by default — feeding it through the
// custom-hash path must yield identical results to the fast path.
func TestHashROR13_MatchesPackageDefault(t *testing.T) {
	r := NewHashGateWith(HashROR13)
	ssn, err := r.Resolve("NtClose")
	require.NoError(t, err)

	def := NewHashGate()
	defSSN, err := def.Resolve("NtClose")
	require.NoError(t, err)

	assert.Equal(t, defSSN, ssn)
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
