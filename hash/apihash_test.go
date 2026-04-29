package hash

import "testing"

// Reference vectors computed once via stdlib (`hash/fnv`,
// `hash/crc32`) and the canonical Jenkins / DJB2 implementations.
// Pin the implementation against these to catch any regression
// in the fast in-line versions.

func TestFNV1a32_KnownVectors(t *testing.T) {
	cases := map[string]uint32{
		"kernel32.dll": 0xa3e6f6c3,
		"LoadLibraryA": 0x53b2070f,
		"":             0x811c9dc5, // FNV-1a 32-bit offset basis
	}
	for in, want := range cases {
		if got := FNV1a32(in); got != want {
			t.Errorf("FNV1a32(%q) = %#x, want %#x", in, got, want)
		}
	}
}

func TestFNV1a64_KnownVectors(t *testing.T) {
	cases := map[string]uint64{
		"kernel32.dll": 0xe14b18a7acf9c443,
		"":             0xcbf29ce484222325, // FNV-1a 64-bit offset basis
	}
	for in, want := range cases {
		if got := FNV1a64(in); got != want {
			t.Errorf("FNV1a64(%q) = %#x, want %#x", in, got, want)
		}
	}
}

func TestJenkinsOAAT_KnownVectors(t *testing.T) {
	cases := map[string]uint32{
		"kernel32.dll": 0xd4250f59,
		"LoadLibraryA": 0xec33d795,
		"":             0x0,
	}
	for in, want := range cases {
		if got := JenkinsOAAT(in); got != want {
			t.Errorf("JenkinsOAAT(%q) = %#x, want %#x", in, got, want)
		}
	}
}

func TestDJB2_KnownVectors(t *testing.T) {
	cases := map[string]uint32{
		"kernel32.dll": 0x7040ee75,
		"LoadLibraryA": 0x5fbff0fb,
		"":             0x1505, // DJB2 initial seed (5381)
	}
	for in, want := range cases {
		if got := DJB2(in); got != want {
			t.Errorf("DJB2(%q) = %#x, want %#x", in, got, want)
		}
	}
}

func TestCRC32_MatchesIEEE(t *testing.T) {
	cases := map[string]uint32{
		"kernel32.dll": 0x6ae69f02,
		"":             0,
	}
	for in, want := range cases {
		if got := CRC32(in); got != want {
			t.Errorf("CRC32(%q) = %#x, want %#x", in, got, want)
		}
	}
}

// TestAlgorithms_DistinctOnSameInput is a sanity guard: every
// algorithm produces a different value for the same non-empty
// string. Catches an accidental copy-paste where two functions end
// up implementing the same algorithm.
func TestAlgorithms_DistinctOnSameInput(t *testing.T) {
	const s = "kernel32.dll"
	seen := map[uint32]string{}
	for name, got := range map[string]uint32{
		"ROR13":       ROR13(s),
		"FNV1a32":     FNV1a32(s),
		"JenkinsOAAT": JenkinsOAAT(s),
		"DJB2":        DJB2(s),
		"CRC32":       CRC32(s),
	} {
		if other, dup := seen[got]; dup {
			t.Errorf("%s(%q) = %s(%q) = %#x — collision implies duplicate impl",
				name, s, other, s, got)
		}
		seen[got] = name
	}
}
