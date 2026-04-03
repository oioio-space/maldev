//go:build windows

package api

import (
	"testing"

	"github.com/oioio-space/maldev/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModuleByHash(t *testing.T) {
	base, err := ModuleByHash(HashKernel32)
	require.NoError(t, err)
	assert.NotZero(t, base, "kernel32 base should be non-zero")
}

func TestModuleByHash_Ntdll(t *testing.T) {
	base, err := ModuleByHash(HashNtdll)
	require.NoError(t, err)
	assert.NotZero(t, base, "ntdll base should be non-zero")
}

func TestModuleByHash_NotFound(t *testing.T) {
	_, err := ModuleByHash(0xDEADBEEF)
	assert.Error(t, err)
}

func TestExportByHash(t *testing.T) {
	base, err := ModuleByHash(HashKernel32)
	require.NoError(t, err)

	addr, err := ExportByHash(base, HashLoadLibraryA)
	require.NoError(t, err)
	assert.NotZero(t, addr, "LoadLibraryA address should be non-zero")
}

func TestExportByHash_NotFound(t *testing.T) {
	base, err := ModuleByHash(HashKernel32)
	require.NoError(t, err)

	_, err = ExportByHash(base, 0xDEADBEEF)
	assert.Error(t, err)
}

func TestResolveByHash(t *testing.T) {
	addr, err := ResolveByHash(HashKernel32, HashGetProcAddress)
	require.NoError(t, err)
	assert.NotZero(t, addr, "GetProcAddress address should be non-zero")
}

func TestHashConstants(t *testing.T) {
	// Verify module constants match hash.ROR13Module
	assert.Equal(t, hash.ROR13Module("KERNEL32.DLL"), HashKernel32)
	assert.Equal(t, hash.ROR13Module("ntdll.dll"), HashNtdll)
	assert.Equal(t, hash.ROR13Module("ADVAPI32.dll"), HashAdvapi32)

	// Verify function constants match hash.ROR13
	assert.Equal(t, hash.ROR13("LoadLibraryA"), HashLoadLibraryA)
	assert.Equal(t, hash.ROR13("GetProcAddress"), HashGetProcAddress)
	assert.Equal(t, hash.ROR13("VirtualAlloc"), HashVirtualAlloc)
	assert.Equal(t, hash.ROR13("VirtualProtect"), HashVirtualProtect)
	assert.Equal(t, hash.ROR13("NtAllocateVirtualMemory"), HashNtAllocateVirtualMemory)
	assert.Equal(t, hash.ROR13("NtCreateThreadEx"), HashNtCreateThreadEx)
}
