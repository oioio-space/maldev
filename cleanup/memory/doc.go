// Package memory provides secure memory cleanup primitives for wiping
// sensitive data (shellcode, keys, credentials) from process memory.
//
// Technique: Zero-fill and release allocated memory regions.
// MITRE ATT&CK: T1070 (Indicator Removal)
// Platform: SecureZero and DoSecret are cross-platform; WipeAndFree is Windows-only.
// Detection: Low -- VirtualProtect + VirtualFree are high-volume legitimate calls.
//
// SecureZero overwrites a byte slice with zeros using Go's clear builtin,
// which the compiler treats as an intrinsic and never elides as a dead store.
//
// WipeAndFree (Windows) changes the page protection of a VirtualAlloc'd region
// to RW, writes zeros across it, then releases the pages via VirtualFree.
//
// DoSecret wraps a function call and, when built with Go 1.26+ and
// GOEXPERIMENT=runtimesecret, erases the registers, stack, and heap temporaries
// used by that call. On other builds DoSecret is a plain call with no erasure,
// so callers may wrap sensitive computations unconditionally.
//
// Build matrix:
//
//	Feature      | Min Go | Extra                       | Platforms
//	-------------|--------|-----------------------------|----------------------
//	SecureZero   | 1.21   | -                           | all
//	WipeAndFree  | 1.21   | -                           | windows
//	DoSecret     | 1.21   | stub (no erasure)           | all
//	DoSecret     | 1.26   | GOEXPERIMENT=runtimesecret  | all (erases on linux/amd64+arm64)
//
// Example:
//
//	addr, _ := windows.VirtualAlloc(0, 4096, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
//	// ... use addr ...
//	memory.WipeAndFree(addr, 4096)
//
//	buf := []byte("secret key material")
//	defer memory.SecureZero(buf)
//
//	var derived []byte
//	memory.DoSecret(func() {
//	    tmp := deriveKey(master)
//	    derived = make([]byte, len(tmp))
//	    copy(derived, tmp)
//	})
package memory
