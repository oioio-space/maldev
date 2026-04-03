// Package memory provides secure memory cleanup primitives for wiping
// sensitive data (shellcode, keys, credentials) from process memory.
//
// Technique: Zero-fill and release allocated memory regions.
// MITRE ATT&CK: T1070 (Indicator Removal)
// Platform: Windows
// Detection: Low -- VirtualProtect + VirtualFree are high-volume legitimate calls.
//
// WipeAndFree changes the page protection to RW, writes zeros across the
// region, then releases the pages via VirtualFree. SecureZero overwrites a
// byte slice with zeros using a volatile-style pattern that prevents the
// compiler from eliding the write.
//
// Example:
//
//	addr, _ := windows.VirtualAlloc(0, 4096, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
//	// ... use addr ...
//	memory.WipeAndFree(addr, 4096)
//
//	buf := []byte("secret key material")
//	defer memory.SecureZero(buf)
package memory
