// Package packer is maldev's custom PE/ELF packer.
//
// Phases shipped:
//
//   - 1a — [Pack] / [Unpack] pipeline: AEAD cipher (AES-GCM default)
//     + self-describing maldev-format blob (magic + version + cipher
//     + compressor + sizes + nonce + ciphertext).
//   - 1b — Windows x64 reflective loader stub
//     ([github.com/oioio-space/maldev/pe/packer/runtime]).
//   - 1c — Composability via [PackPipeline] / [UnpackPipeline]:
//     stack [PipelineOp] steps ([OpCipher] / [OpPermute] /
//     [OpCompress] / [OpEntropyCover]) in any order; each step's
//     algorithm is wire-recorded but its key never is.
//   - 1c.5 — Compression in pipeline ([CompressorFlate],
//     [CompressorGzip] via stdlib).
//   - 1d — Anti-entropy under [OpEntropyCover]:
//     [EntropyCoverInterleave] (low-entropy padding spliced
//     between ciphertext chunks — drops real Shannon entropy
//     proportional to padding ratio), [EntropyCoverCarrier]
//     (PNG-shaped 32-byte header so first-bytes scanners don't
//     fire), [EntropyCoverHexAlphabet] (each byte → 2 alphabet
//     bytes, apparent entropy ≤ 4 bits/byte).
//   - 1e (v0.61.0) — UPX-style in-place transform via [PackBinary]:
//     encrypts the input binary's .text section with SGN polymorphic
//     encoding (XOR/SUB/ADD rounds with register randomisation and
//     junk insertion), appends a compact polymorphic decoder stub as a
//     new R+W+X section (CALL+POP+ADD prologue for position-independent
//     address recovery, N decoder loops, final JMP to original entry),
//     and rewrites the entry-point field. Output is a single
//     self-contained binary — no stage 2, no reflective loader. The
//     kernel loads the output normally; the stub decrypts in place.
//     Supports [FormatWindowsExe] (PE32+) and [FormatLinuxELF]
//     (ELF64 static-PIE). Detection is Medium-High: UPX-like
//     single-binary packer patterns are well-known to AV/EDR; stub
//     bytes differ per pack (polymorphic) which defeats hash-based
//     batch detection, but the RWX new section and entry-point
//     rewrite are heuristically suspicious.
//   - 3a (post-v0.61.0) — Anti-static-unpacker cover layer via
//     [AddCoverPE] / [AddCoverELF] / [ApplyDefaultCover]: appends
//     junk sections (PE) or junk PT_LOADs (ELF) with caller-chosen
//     [JunkFill] strategy ([JunkFillRandom] for ~8 bits/byte
//     entropy, [JunkFillZero] for flat-entropy padding,
//     [JunkFillPattern] for machine-code-shaped histograms). The
//     cover sections carry MEM_READ only — kernel maps them but
//     never executes; runtime path is unchanged. Pair with
//     [PackBinary] to inflate the static surface and frustrate
//     fingerprints that match on exact section count + offset.
//     [DefaultCoverOptions] picks 3 reasonable sections and is
//     exposed via [ApplyDefaultCover] for one-liner integration.
//
// The full design (capability matrix, threat model, hard
// constraints, phase plan) is at
// docs/refactor-2026-doc/packer-design.md.
//
// # MITRE ATT&CK
//
//   - T1027.002 — Obfuscated Files or Information: Software Packing
//   - T1620 — Reflective Code Loading (Phase 1b onwards, when the
//     reflective stub ships)
//
// # Detection level
//
// moderate.
//
// The pack-time pipeline (Phases 1a / 1c / 1d / 3a) is pure-Go
// offline byte manipulation — no syscalls, no network, no
// runtime artefacts. Detection of those layers is purely static:
// the blob's [Magic] prefix is fingerprintable when the blob is
// shipped raw, but in practice it travels inside a host binary
// that obscures it.
//
// Phase 1e ([PackBinary]) emits a runnable PE/ELF whose
// CALL+POP+ADD prologue + new R+W+X section + entry-point
// rewrite is heuristically suspicious to AV/EDR static scans.
// Per-pack stub-byte uniqueness from the SGN engine defeats
// hash-based batch detection, but the structural shape is
// well-known. Pair with [AddCoverPE] / [AddCoverELF] /
// [ApplyDefaultCover] to inflate the static surface and
// frustrate fingerprints that match on exact section count +
// offset, plus [EntropyCoverInterleave] / [EntropyCoverHexAlphabet]
// in the [PackPipeline] path to drop apparent histogram entropy
// below 4 bits/byte.
//
// # Required privileges
//
// unprivileged. The packer is pack-time only; runtime artefacts
// are produced by the loader (kernel for [PackBinary] outputs,
// [github.com/oioio-space/maldev/pe/packer/runtime] for
// reflective loads).
//
// # Platform
//
// Cross-platform pack-time. [PackBinary] outputs are per-target
// ([FormatWindowsExe] PE32+ runs on Windows; [FormatLinuxELF]
// runs on Linux). [Pack] / [PackPipeline] outputs are
// architecture-neutral blobs. The reflective loader
// ([github.com/oioio-space/maldev/pe/packer/runtime]) ships for
// Windows x64 and Linux ELF64 (Phase 1f Stages A–E).
//
// # Example
//
// See [Example] suite in [packer_example_test.go]:
// [ExamplePack], [ExamplePackBinary], [ExampleAddCoverPE],
// [ExampleApplyDefaultCover].
//
// One-liner Phase 1e + cover for Linux ELF input:
//
//	out, _, err := packer.PackBinary(payload, packer.PackBinaryOptions{
//	    Format: packer.FormatLinuxELF, Stage1Rounds: 3, Seed: 1,
//	})
//	if err != nil { /* … */ }
//	if covered, err := packer.ApplyDefaultCover(out, 2); err == nil {
//	    out = covered
//	}
//
// # See also
//
//   - docs/techniques/pe/packer.md — operator-facing tech md
//   - docs/refactor-2026-doc/packer-design.md — full design doc
//   - [github.com/oioio-space/maldev/pe/morph] — UPX section rename
//     (adjacent technique; both ship, different problems)
//   - [github.com/oioio-space/maldev/pe/srdi] — Donut shellcode
//     (alternative path; packer is "Donut for PEs on disk")
//
// [github.com/oioio-space/maldev/pe/morph]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/morph
// [github.com/oioio-space/maldev/pe/srdi]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi
package packer
