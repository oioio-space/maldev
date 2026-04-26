package samdump

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// Boot-key (a.k.a. syskey) extraction from a SYSTEM hive.
//
// The boot key is a 16-byte AES/RC4 key Microsoft scatters across
// four subkey class-name strings under
// `ControlSet001\Control\Lsa`:
//
//	JD\Class    → 8 hex chars → 4 bytes
//	Skew1\Class → 8 hex chars → 4 bytes
//	GBG\Class   → 8 hex chars → 4 bytes
//	Data\Class  → 8 hex chars → 4 bytes
//
// The 16 bytes are then re-ordered through a fixed permutation
// (bootKeyPermutation below) to recover the actual key.
//
// Algorithm reference: impacket secretsdump.py LOCAL handler;
// SharpKatz Module/Sam.cs `getBootKey`. Both implementations
// independently derive the same permutation.

// ErrBootKey is returned when the SYSTEM hive's
// `Lsa\{JD,Skew1,GBG,Data}` subkeys are missing, their class names
// are absent, or the hex decode fails. The wrapped error names the
// failing subkey so the operator can spot a corrupted hive.
var ErrBootKey = errors.New("samdump: boot-key extraction failed")

// bootKeyPermutation is the 16-byte re-ordering Microsoft applies
// to the concatenated JD || Skew1 || GBG || Data bytes. Stable
// across every Windows release since NT 4.0 SP3 (when SysKey
// shipped); both impacket and SharpKatz hard-code these positions.
var bootKeyPermutation = [16]int{
	8, 5, 4, 2, 11, 9, 13, 3,
	0, 6, 1, 12, 14, 10, 15, 7,
}

// bootKeySubkeys names the four subkey paths the algorithm reads, in
// the concatenation order (JD first, Data last). Each subkey's class
// name contributes 4 raw bytes.
var bootKeySubkeys = [4]string{"JD", "Skew1", "GBG", "Data"}

// systemControlSetPath is the hive path prefix where the four
// boot-key subkeys live. ControlSet001 is the canonical path; on
// modern Windows this is always the active set (the `Select` key's
// `Current` value also points at it). Operators with a non-standard
// hive can register a different path via extractBootKeyFromPath.
const systemControlSetPath = `ControlSet001\Control\Lsa`

// extractBootKey returns the 16-byte boot key of the SYSTEM hive.
// Wrapping every failure path in ErrBootKey so callers can dispatch
// with a single errors.Is.
func extractBootKey(system *hive) ([]byte, error) {
	return extractBootKeyFromPath(system, systemControlSetPath)
}

// extractBootKeyFromPath is the override-friendly form of
// extractBootKey. lsaPath is the hive path of the parent key whose
// JD/Skew1/GBG/Data subkeys carry the bootkey class names.
func extractBootKeyFromPath(system *hive, lsaPath string) ([]byte, error) {
	lsa, err := system.openPath(lsaPath)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrBootKey, lsaPath, err)
	}

	var raw [16]byte
	for i, name := range bootKeySubkeys {
		sub, err := system.openSubkey(lsa, name)
		if err != nil {
			return nil, fmt.Errorf("%w: subkey %s: %v", ErrBootKey, name, err)
		}
		class, err := system.readClassName(sub)
		if err != nil {
			return nil, fmt.Errorf("%w: read class %s: %v", ErrBootKey, name, err)
		}
		// Each class string carries 8 hex chars (lowercase or upper).
		// hex.DecodeString tolerates both. Reject any other length —
		// junk class names are a sign of a corrupted or wrong hive.
		if len(class) != 8 {
			return nil, fmt.Errorf("%w: subkey %s class %q has length %d, want 8 hex chars",
				ErrBootKey, name, class, len(class))
		}
		decoded, err := hex.DecodeString(class)
		if err != nil {
			return nil, fmt.Errorf("%w: subkey %s class %q hex decode: %v",
				ErrBootKey, name, class, err)
		}
		copy(raw[i*4:i*4+4], decoded)
	}

	// Apply the permutation.
	out := make([]byte, 16)
	for i, src := range bootKeyPermutation {
		out[i] = raw[src]
	}
	return out, nil
}

// permuteBootKey is split out for unit testing — operators don't
// call it directly. Given 16 raw bytes (the JD||Skew1||GBG||Data
// concatenation), returns the permuted 16-byte boot key.
func permuteBootKey(raw [16]byte) []byte {
	out := make([]byte, 16)
	for i, src := range bootKeyPermutation {
		out[i] = raw[src]
	}
	return out
}
