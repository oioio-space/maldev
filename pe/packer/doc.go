// Package packer is maldev's custom PE/ELF packer.
//
// Today (Phase 1a) the package ships only the encrypt + embed
// pipeline: [Pack] takes any byte buffer, runs it through an
// AEAD cipher (AES-GCM by default), and emits a self-describing
// maldev-format blob (magic + version + cipher + compressor +
// sizes + nonce + ciphertext). [Unpack] reverses the pipeline
// given the original key.
//
// The Phase 1a output is NOT a runnable PE — it's an opaque blob.
// The reflective loader stub that wraps the blob into a runnable
// PE/ELF lands in Phase 1b. The full design (3 phases, capability
// matrix, threat model, hard constraints) is at
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
// very-quiet (Phase 1a)
//
// Pure pack-time pipeline — no syscalls, no network, no runtime
// artefacts. The blob bytes themselves carry an [Magic] prefix
// that defenders fingerprint trivially today; this is acceptable
// because the Phase 1a blob is never deployed alone (it's wrapped
// in a runnable PE host by Phase 1b which obscures the magic).
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
