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

// RandomUniqueSectionName draws a fresh [RandomStubSectionName]
// that doesn't appear in `used`, retrying up to 4 times. With a
// 26⁵ ≈ 11.8M name space and PE/COFF max 96 sections, the
// probability of needing more than 4 attempts is below 1e-3 —
// the cap is a defence-in-depth, not a correctness requirement.
// The drawn name is NOT appended to `used`; the caller is
// expected to do that so multi-step namers can interleave logic.
func RandomUniqueSectionName(rng *rand.Rand, used [][8]byte) [8]byte {
	var name [8]byte
	for attempt := 0; attempt < 4; attempt++ {
		name = RandomStubSectionName(rng)
		collision := false
		for _, u := range used {
			if u == name {
				collision = true
				break
			}
		}
		if !collision {
			return name
		}
	}
	return name
}
