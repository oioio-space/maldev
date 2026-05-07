// Package transform implements UPX-style in-place modification of
// input PE/ELF binaries. Given a runnable input + an encrypted-text
// blob + a stub bytes blob, transform produces a modified binary
// that:
//
//   - Has its .text section replaced with encrypted bytes (RWX flags)
//   - Has a new section appended containing the stub (R+E flags)
//   - Has its entry point rewritten to the new stub section
//   - Preserves all other sections byte-for-byte (so the kernel's
//     IAT bind / relocation / resource lookup work unchanged)
//
// At runtime the kernel loads the modified binary normally and gives
// control to the stub; the stub decrypts .text in place and JMPs to
// the original OEP.
//
// Two-phase API:
//   - PlanPE / PlanELF compute the layout (RVAs, file offsets, sizes)
//     from the input alone. Returned Plan feeds the stub generator
//     (which needs RVAs to bake into the asm).
//   - InjectStubPE / InjectStubELF apply the planned mutations
//     given the encrypted-text bytes and the emitted stub bytes.
//
// # Detection level
//
// N/A — pack-time only. The modified binary at runtime is "loud"
// (RWX section, new entry point not in the original code section).
// Pair with evasion/sleepmask + evasion/preset for memory-side cover.
//
// # See also
//
//   - pe/morph — low-level section-header byte manipulation
//   - pe/strip — in-place PE byte mutation primitives
//   - Microsoft PE/COFF Specification Rev 12.0
//   - System V ABI AMD64 Rev 1.0
package transform
