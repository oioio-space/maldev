package transform

import "math/rand"

// RandomStubSectionName returns an 8-byte PE section name suitable
// for [Plan.StubSectionName]. Format: '.' + 5 random ASCII letters
// + 2 NUL bytes. The leading '.' matches the convention every
// MSVC linker uses for built-in sections (.text, .rdata, .data,
// .pdata, .reloc, …) so the random name doesn't stand out as
// "operator-emitted".
//
// Deterministic given a seeded *rand.Rand — the same seed across
// two packs produces the same name, useful for reproducible-build
// tests. Pass a fresh-seeded rand for true per-pack uniqueness.
//
// Phase 2-A of the packer-design plan: defeats YARA rules keyed
// on the literal ".mldv" string the packer emits by default.
func RandomStubSectionName(rng *rand.Rand) [8]byte {
	var name [8]byte
	name[0] = '.'
	const letters = "abcdefghijklmnopqrstuvwxyz"
	for i := 1; i <= 5; i++ {
		name[i] = letters[rng.Intn(len(letters))]
	}
	// name[6] and name[7] stay NUL — PE section names are NUL-padded.
	return name
}
