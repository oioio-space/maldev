// Package morph mutates UPX-packed PE headers so automatic
// unpackers fail to recognise the input.
//
// UPX writes its signature ("UPX!") at fixed offsets in section
// headers and at the end of l_info. Standard unpackers
// (CFF Explorer, x64dbg's UPX plugin, IDA's UPX preprocessor)
// match those bytes literally — replacing them with random
// non-zero bytes preserves the unpack pipeline UPX itself
// emits at runtime (the stub references offsets, not the magic)
// while breaking off-the-shelf static unpackers.
//
// [UPXFix] reverses the mutation by restoring the canonical
// signature, useful for debugging or for legitimate
// re-distribution.
//
// # MITRE ATT&CK
//
//   - T1027.002 (Obfuscated Files or Information: Software Packing) — UPX header mutation
//
// # Detection level
//
// moderate
//
// Modified UPX headers prevent standard unpackers but the PE
// structure (executable section count, entropy) remains
// recognisable. Anti-malware that fingerprints UPX-packed
// binaries by entropy + section layout will still flag the
// file; only signature-based unpacker matching is defeated.
//
// # Example
//
// See [ExampleUPXMorph] in morph_example_test.go.
//
// # See also
//
//   - docs/techniques/pe/morph.md
//   - [github.com/oioio-space/maldev/pe/strip] — pair with strip for full scrub
//   - [github.com/oioio-space/maldev/hash] — fuzzy-hash the morphed output
//
// [github.com/oioio-space/maldev/pe/strip]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/strip
// [github.com/oioio-space/maldev/hash]: https://pkg.go.dev/github.com/oioio-space/maldev/hash
package morph
