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
// # MITRE ATT&CK
//
//   - T1027.002 (Obfuscated Files or Information: Software Packing) —
//     transform is the in-place mutation engine the parent
//     [github.com/oioio-space/maldev/pe/packer] package drives.
//
// # Detection level
//
// noisy.
//
// Pure pack-time package — no syscalls, no runtime artefacts. The
// modified output is "loud" at runtime (RWX section, entry point
// rewritten outside the original code section); pair with
// [github.com/oioio-space/maldev/evasion/sleepmask] +
// [github.com/oioio-space/maldev/evasion/preset] for memory-side
// cover.
//
// # Required privileges
//
// unprivileged.
//
// # Platform
//
// Cross-platform pack-time. Output binaries run on Windows
// (FormatPE) or Linux (FormatELF).
//
// # Example
//
// See [Example] suite in transform's `*_test.go` files (PlanPE_HappyPath,
// InjectStubELF_DebugELFParses) for round-trip patterns.
//
// # See also
//
//   - [github.com/oioio-space/maldev/pe/morph] — low-level section-header
//     byte manipulation
//   - [github.com/oioio-space/maldev/pe/strip] — in-place PE byte mutation
//     primitives
//   - Microsoft PE/COFF Specification Rev 12.0
//   - System V ABI AMD64 Rev 1.0
//   - docs/techniques/pe/packer.md — operator-facing tech md
package transform
