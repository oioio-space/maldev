//go:build windows

// Package api is the single source of truth for all Windows DLL handles,
// procedure references, and shared structures used across the maldev library.
//
// Platform: Windows
// Detection: Low -- loading system DLLs is normal process behavior.
//
// All other maldev modules MUST import DLL handles and procedure pointers
// from this package instead of declaring their own LazyDLL instances.
// This prevents duplicate handles and ensures consistent DLL search path
// restriction via NewLazySystemDLL (which limits loading to System32).
//
// Exported DLL handles: Kernel32, Ntdll, Advapi32, User32, Shell32, Userenv, Netapi32.
//
// # API Hashing (PEB Walk)
//
// Technique: Runtime function resolution via PEB walk and ROR13 export hashing.
// MITRE ATT&CK: T1106 (Native API)
// Detection: Low — PEB and export table are user-mode readable memory.
//
// ResolveByHash, ModuleByHash, and ExportByHash walk the PEB's
// InLoadOrderModuleList to find loaded DLLs by hash, then parse the PE
// export directory to find functions by hash. No plaintext API names
// are needed — only uint32 ROR13 hashes. Pre-computed constants are
// provided for common modules (HashKernel32, HashNtdll) and functions
// (HashLoadLibraryA, HashGetProcAddress, HashNtAllocateVirtualMemory, etc.).
//
// Example:
//
//	addr, err := api.ResolveByHash(api.HashKernel32, api.HashLoadLibraryA)
//	// addr is the address of LoadLibraryA — no string "LoadLibraryA" in the binary
package api
