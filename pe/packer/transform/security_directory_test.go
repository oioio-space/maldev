package transform_test

import (
	"encoding/binary"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// TestStripPESecurityDirectory_ZeroesEntry — the v0.126.0 cert
// strip: PackBinary's .text mutation invalidates any
// Authenticode signature, so we zero DataDirectory[SECURITY]
// to render the output cleanly "unsigned" rather than
// "signed-but-tampered".
func TestStripPESecurityDirectory_ZeroesEntry(t *testing.T) {
	pe := minPEWithASLR(t)
	const (
		peOff   = 0x40
		coffOff = peOff + 4
		optOff  = coffOff + transform.PECOFFHdrSize
	)
	// Stamp non-zero SECURITY directory entry to verify the strip
	// actually fires.
	secEntry := optOff + transform.OptDataDirsStart + 4*transform.OptDataDirEntrySize
	binary.LittleEndian.PutUint32(pe[secEntry:], 0x12345678)
	binary.LittleEndian.PutUint32(pe[secEntry+4:], 0x00001234)

	if err := transform.StripPESecurityDirectory(pe); err != nil {
		t.Fatalf("StripPESecurityDirectory: %v", err)
	}
	if got := binary.LittleEndian.Uint32(pe[secEntry:]); got != 0 {
		t.Errorf("SECURITY VirtualAddress = 0x%x, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(pe[secEntry+4:]); got != 0 {
		t.Errorf("SECURITY Size = 0x%x, want 0", got)
	}
}

// TestStripPESecurityDirectory_ZeroEntryNoop — already-stripped
// PE returns nil cleanly.
func TestStripPESecurityDirectory_ZeroEntryNoop(t *testing.T) {
	pe := minPEWithASLR(t)
	if err := transform.StripPESecurityDirectory(pe); err != nil {
		t.Errorf("strip on already-zero entry: want nil, got %v", err)
	}
}

func TestStripPESecurityDirectory_RejectsTruncated(t *testing.T) {
	if err := transform.StripPESecurityDirectory([]byte{0x4D, 0x5A}); err == nil {
		t.Error("strip on 2-byte input: want error, got nil")
	}
}
