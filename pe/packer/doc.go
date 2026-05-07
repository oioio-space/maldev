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
// very-quiet (Phase 1a–1d)
//
// Pure pack-time pipeline — no syscalls, no network, no runtime
// artefacts. The blob bytes themselves carry a [Magic] prefix
// that defenders fingerprint trivially today; this is acceptable
// because the blob is never deployed alone (it's wrapped in a
// runnable PE host by Phase 1b which obscures the magic).
//
// Stack [EntropyCoverInterleave] + [EntropyCoverHexAlphabet] as
// the last pipeline steps to drop apparent histogram entropy
// below 4 bits/byte — defeats Shannon-based AV scanners.
//
// # Required privileges
//
// unprivileged. [Pack] is pure-Go offline byte manipulation;
// [Unpack] is symmetric.
//
// # Platform
//
// Cross-platform (emitter side). The blob format is
// architecture-neutral. Phase 1b's reflective loader will be
// per-target (Windows PE32+, Linux ELF64).
//
// # Example
//
//	import "github.com/oioio-space/maldev/pe/packer"
//
//	// Pack: returns the blob + the AEAD key.
//	blob, key, err := packer.Pack(payloadBytes, packer.Options{
//	    Cipher:     packer.CipherAESGCM,
//	    Compressor: packer.CompressorNone,
//	})
//	if err != nil { /* … */ }
//
//	// Round-trip: decrypts back to the original payload.
//	orig, err := packer.Unpack(blob, key)
//	if err != nil { /* … */ }
//	_ = orig
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
