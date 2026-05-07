// Package host emits the host binaries that wrap stage-1 polymorphic
// asm bytes + encoded stage-2 + payload blobs.
//
// Two formats today:
//   - EmitPE — Windows PE32+ executable (Phase 1e-A)
//   - EmitELF — Linux ELF64 LE x86_64 static-PIE (Phase 1e-B)
//
// Both are hand-emitted from raw bytes — no debug/* (read-only),
// no external linker. References:
//   - Microsoft PE/COFF Specification Rev 12.0 (PE)
//   - System V ABI AMD64 Architecture Processor Supplement Rev 1.0 (ELF)
//
// # Detection level
//
// N/A — pack-time only. The emitted hosts are loud at runtime
// (highly observable as freshly-allocated RWX'd images); pair
// with evasion/sleepmask + evasion/preset for memory cover.
package host
