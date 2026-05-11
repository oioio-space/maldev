package stage1_test

import (
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
)

// TestRor13HashASCII_KnownValues pins a handful of hashes so a
// future micro-tweak to the loop (different rotation count, byte vs
// int promotion, signed/unsigned shift) trips the test instead of
// silently producing a packed binary that resolves the wrong API.
func TestRor13HashASCII_KnownValues(t *testing.T) {
	cases := []struct {
		input string
		want  uint32
	}{
		{"", 0x00000000},
		// Pinned values for OUR ROR-13 + XOR variant. Stephen Fewer's
		// canonical shellcode uses ROR-13 + ADD which yields different
		// constants (0x71019A4F for "CreateThread"); the XOR variant is
		// what our asm template emits, so the helper must match it.
		// Drift here means the splice would point at the wrong export.
		// Recomputed offline:
		//   h := uint32(0)
		//   for _, c := range []byte(name) { h = (h>>13|h<<19) ^ uint32(c) }
		{"CreateThread", 0x071FBF92},
		{"ExitProcess", 0xEDDD279B},
		// Single-byte: hash starts at 0, ror(0,13)=0, XOR 'A'=0x41 → 0x41.
		{"A", 0x41},
	}
	for _, c := range cases {
		got := stage1.Ror13HashASCII(c.input)
		if got != c.want {
			t.Errorf("Ror13HashASCII(%q) = %#x, want %#x", c.input, got, c.want)
		}
	}
}

// TestRor13HashASCII_CaseSensitive — export-name hashing must NOT
// fold case (Windows export tables are case-sensitive).
func TestRor13HashASCII_CaseSensitive(t *testing.T) {
	upper := stage1.Ror13HashASCII("CreateThread")
	lower := stage1.Ror13HashASCII("createthread")
	if upper == lower {
		t.Errorf("hash collision: %q and %q both = %#x", "CreateThread", "createthread", upper)
	}
}

// TestRor13HashUnicodeUpper_FoldsCase — module-name hashing MUST
// fold lowercase ASCII so PEB BaseDllName variants
// ("KERNEL32.DLL" / "kernel32.dll" / "Kernel32.dll") collapse to
// the same hash.
func TestRor13HashUnicodeUpper_FoldsCase(t *testing.T) {
	h1 := stage1.Ror13HashUnicodeUpper("kernel32.dll")
	h2 := stage1.Ror13HashUnicodeUpper("KERNEL32.DLL")
	h3 := stage1.Ror13HashUnicodeUpper("Kernel32.Dll")
	if h1 != h2 || h2 != h3 {
		t.Errorf("case folding broken: %#x / %#x / %#x", h1, h2, h3)
	}
}

// TestRor13HashUnicodeUpper_NonASCII — non-ASCII code points (>0x7E)
// must pass through unchanged (the asm's `cmp eax, 0x7a / ja
// .no_lowercase` skips the subtraction for them).
func TestRor13HashUnicodeUpper_NonASCII(t *testing.T) {
	// 'é' (U+00E9) > 0x7A so it's not folded. The hash must depend on
	// the raw code point, not on '~' / 0x7E.
	a := stage1.Ror13HashUnicodeUpper("é")
	b := stage1.Ror13HashUnicodeUpper("~")
	if a == b {
		t.Errorf("non-ASCII collision: 'é'=%#x '~'=%#x", a, b)
	}
}

// TestKernel32DLLHash_MatchesFolded — the package-level constant
// must equal the case-folded hash; documents the value for
// future asm audits.
func TestKernel32DLLHash_MatchesFolded(t *testing.T) {
	want := stage1.Ror13HashUnicodeUpper("kernel32.dll")
	if stage1.Kernel32DLLHash != want {
		t.Errorf("Kernel32DLLHash = %#x, want %#x", stage1.Kernel32DLLHash, want)
	}
	if stage1.Kernel32DLLHash == 0 {
		t.Error("Kernel32DLLHash unexpectedly zero — sanity check")
	}
}
