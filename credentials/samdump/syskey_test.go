package samdump

import (
	"bytes"
	"errors"
	"testing"
)

func TestPermuteBootKey_KnownVector(t *testing.T) {
	// Vector cross-checked against impacket secretsdump.py:
	//   raw = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
	//   perm = [8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7]
	//   out = bytes(raw[p] for p in perm)
	//        = 08 05 04 02 0b 09 0d 03 00 06 01 0c 0e 0a 0f 07
	raw := [16]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}
	want := []byte{
		0x08, 0x05, 0x04, 0x02, 0x0B, 0x09, 0x0D, 0x03,
		0x00, 0x06, 0x01, 0x0C, 0x0E, 0x0A, 0x0F, 0x07,
	}
	got := permuteBootKey(raw)
	if !bytes.Equal(got, want) {
		t.Fatalf("permuteBootKey:\n  got  % X\n  want % X", got, want)
	}
}

func TestPermuteBootKey_AllZeros(t *testing.T) {
	var raw [16]byte
	got := permuteBootKey(raw)
	for i, b := range got {
		if b != 0 {
			t.Errorf("permuteBootKey[%d] = 0x%02X, want 0x00", i, b)
		}
	}
}

func TestPermuteBootKey_PermutationIsBijection(t *testing.T) {
	// Sanity check on the permutation table itself: every output
	// position must source from a unique input position; every input
	// position must be referenced exactly once.
	seen := [16]bool{}
	for _, src := range bootKeyPermutation {
		if src < 0 || src >= 16 {
			t.Fatalf("permutation source %d out of [0,16)", src)
		}
		if seen[src] {
			t.Fatalf("permutation source %d repeated", src)
		}
		seen[src] = true
	}
}

func TestExtractBootKey_PropagatesPathFailure(t *testing.T) {
	// Hive with a valid REGF header but no HBIN payload — openPath
	// will fail trying to dereference the root cell.
	body := make([]byte, regfBaseBlockSz)
	copy(body, []byte(regfMagic))

	h, err := readHive(&fakeReaderAt{b: body}, int64(len(body)))
	if err != nil {
		t.Fatalf("readHive: %v", err)
	}
	_, err = extractBootKey(h)
	if !errors.Is(err, ErrBootKey) {
		t.Fatalf("err = %v, want wrap of ErrBootKey", err)
	}
}

func TestBootKeySubkeys_OrderIsCanonical(t *testing.T) {
	// Locks down the JD/Skew1/GBG/Data ordering — flipping any pair
	// would silently produce a wrong boot key on every Windows host.
	want := [4]string{"JD", "Skew1", "GBG", "Data"}
	if bootKeySubkeys != want {
		t.Errorf("bootKeySubkeys = %v, want %v", bootKeySubkeys, want)
	}
}
