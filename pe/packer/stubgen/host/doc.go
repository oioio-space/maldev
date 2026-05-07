// Package host emits a minimal Windows PE32+ executable that
// wraps stage-1 asm bytes (in .text) and the encoded stage-2 +
// payload (in .maldev).
//
// The emitter writes raw bytes — no debug/pe (read-only), no
// external linker. References Microsoft PE/COFF Specification
// Rev 12.0; the layout is intentionally minimal:
//
//	DOS Header (0x40 bytes; 'MZ' + e_lfanew @ 0x3C)
//	PE Signature ("PE\0\0")
//	COFF File Header (0x14 bytes; Machine = 0x8664)
//	Optional Header PE32+ (0xF0 bytes; Magic = 0x20B)
//	Section Table (0x28 bytes per section)
//	Section bodies (file-aligned to 0x200, mem-aligned to 0x1000)
//
// # Detection level
//
// N/A — pack-time only. The emitted PE itself is loud (highly
// observable as a freshly-allocated RWX'd image at runtime); pair
// with evasion/sleepmask + evasion/preset for memory cover.
package host
