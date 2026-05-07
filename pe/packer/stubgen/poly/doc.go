// Package poly implements the SGN-style metamorphic engine the
// Phase 1e-A packer uses to generate polymorphic stage-1
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
// # Detection level
//
// N/A — pack-time only.
package poly
