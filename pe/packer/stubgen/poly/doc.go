// Package poly implements the SGN-style metamorphic engine the
// Phase 1e (v0.61.x) packer uses to generate polymorphic stage-1
// decoders.
//
// Reference: Ege Balci, "Shikata Ga Nai (Encoder Still) Ain't Got
// Nothin' On Me!", Black Hat USA 2018. The original SGN tool
// (github.com/EgeBalci/sgn) is GPL-licensed and depends on
// keystone (CGO) — this package re-implements the algorithm in
// pure Go on top of pe/packer/stubgen/amd64 (which wraps
// golang-asm) so the maldev packer stays a pure library.
//
// The four metamorphic levers SGN exposes are implemented in
// separate files for clarity:
//
//   - substitution.go — equivalence rewrites (XOR ↔ SUB-neg ↔ ADD-comp)
//   - regalloc.go — randomized register pool
//   - junk.go — NOP variants + dead-op insertion
//   - engine.go — N-round chained encoder driver
//
// # MITRE ATT&CK
//
//   - T1027.002 (Obfuscated Files or Information: Software Packing) —
//     polymorphism layer for the parent
//     [github.com/oioio-space/maldev/pe/packer] package's stage-1
//     decoder.
//
// # Detection level
//
// quiet.
//
// Pure pack-time package — emits machine-code bytes only. No
// runtime presence. Each pack produces unique decoder bytes so
// hash-based AV signatures don't transfer between packs; pattern-
// based EDR rules that match on SGN-shape decoders (counter
// register + per-byte XOR + RET-walk) still fire.
//
// # Required privileges
//
// unprivileged.
//
// # Platform
//
// Cross-platform pack-time. Generated decoders are amd64-only
// (the package emits AMD64 instruction byte sequences).
//
// # Example
//
// See round-trip tests in poly_test.go
// (TestEngine_EncodeDecodeRoundTrip / _RoundTripPerSubst).
//
// # See also
//
//   - [github.com/oioio-space/maldev/pe/packer/stubgen/stage1] — consumer
//     of poly.Round descriptors
//   - [github.com/oioio-space/maldev/pe/packer/stubgen/amd64] —
//     instruction emitter under the engine
//   - docs/techniques/pe/packer.md
package poly
