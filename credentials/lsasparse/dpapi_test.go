package lsasparse

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/oioio-space/maldev/credentials/lsassdump"
)

// TestDPAPIMasterKey_AuthPackage covers the interface contract.
func TestDPAPIMasterKey_AuthPackage(t *testing.T) {
	if got := (DPAPIMasterKey{}).AuthPackage(); got != "DPAPI" {
		t.Errorf("AuthPackage = %q, want DPAPI", got)
	}
}

// TestDPAPIMasterKey_GUIDString verifies the 8-4-4-4-12 hyphenated
// format, including the LE-on-first-three / BE-on-last-two swap that
// trips up most ad-hoc GUID printers.
func TestDPAPIMasterKey_GUIDString(t *testing.T) {
	mk := DPAPIMasterKey{
		// Bytes for 9CC0C2D9-89A6-4B4A-8B11-7B0F0E1234AB.
		// LE: D9 C2 C0 9C  A6 89  4A 4B
		// BE: 8B 11  7B 0F 0E 12 34 AB
		KeyGUID: [16]byte{
			0xD9, 0xC2, 0xC0, 0x9C, // data1 LE
			0xA6, 0x89, // data2 LE
			0x4A, 0x4B, // data3 LE
			0x8B, 0x11, // data4 BE
			0x7B, 0x0F, 0x0E, 0x12, 0x34, 0xAB, // node BE
		},
	}
	got := mk.GUIDString()
	want := "9cc0c2d9-89a6-4b4a-8b11-7b0f0e1234ab"
	if got != want {
		t.Errorf("GUIDString = %q, want %q", got, want)
	}
}

// TestDPAPIMasterKey_String verifies the {GUID}:hex emit format
// downstream blob decryptors expect.
func TestDPAPIMasterKey_String(t *testing.T) {
	mk := DPAPIMasterKey{
		KeyGUID:  [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
		KeyBytes: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	got := mk.String()
	want := "{04030201-0605-0807-090a-0b0c0d0e0f10}:deadbeef"
	if got != want {
		t.Errorf("String = %q, want %q", got, want)
	}
}

// TestDPAPIMasterKey_Wipe verifies key bytes + GUID are cleared and
// Found is reset.
func TestDPAPIMasterKey_Wipe(t *testing.T) {
	mk := &DPAPIMasterKey{
		LUID:     0xAAAA,
		KeyGUID:  [16]byte{0xFF, 0xFF, 0xFF, 0xFF},
		KeyBytes: []byte{0x11, 0x22, 0x33, 0x44},
		Found:    true,
	}
	keyRef := mk.KeyBytes // capture original slice for post-wipe content check
	mk.wipe()

	if mk.Found {
		t.Error("Found = true after wipe")
	}
	if mk.KeyBytes != nil {
		t.Errorf("KeyBytes = %v, want nil", mk.KeyBytes)
	}
	for i, b := range keyRef {
		if b != 0 {
			t.Errorf("original buffer[%d] = 0x%X after wipe, want 0", i, b)
			break
		}
	}
	if !isAllZero(mk.KeyGUID[:]) {
		t.Error("KeyGUID not zero after wipe")
	}
}

// TestExtractDPAPI_Disabled covers the "DPAPILayout.NodeSize == 0"
// short-circuit — a template that doesn't support DPAPI must skip
// the walker without error and without reading any module bytes.
func TestExtractDPAPI_Disabled(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()
	tmpl := &Template{}
	keys, warnings := extractDPAPI(nil, Module{}, tmpl)
	if keys != nil {
		t.Errorf("keys = %v, want nil when disabled", keys)
	}
	if warnings != nil {
		t.Errorf("warnings = %v, want nil when disabled", warnings)
	}
}

// TestExtractDPAPI_HappyPath builds a synthetic lsasrv.dll mapping
// with one master-key cache node, walks the list, and verifies the
// LUID + GUID + key-bytes round-trip end-to-end.
func TestExtractDPAPI_HappyPath(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()

	const (
		modBase  uint64 = 0x7FF800000000
		modSize         = uint32(0x1000)
		listHead uint64 = modBase + uint64(modSize) + 0x000
		nodeVA   uint64 = modBase + uint64(modSize) + 0x100
	)

	// Module body: pattern + rel32 → listHead.
	moduleBody := make([]byte, modSize)
	pattern := []byte{0xFA, 0xCE, 0xFE, 0xED}
	patternOff := 0x40
	copy(moduleBody[patternOff:], pattern)
	rel32At := patternOff + 4
	rel32 := int32(int64(listHead) - int64(modBase) - int64(rel32At) - 4)
	binary.LittleEndian.PutUint32(moduleBody[rel32At:rel32At+4], uint32(rel32))

	// listHead — circular single-entry list.
	listHeadBytes := make([]byte, 16)
	binary.LittleEndian.PutUint64(listHeadBytes[0:8], nodeVA)
	binary.LittleEndian.PutUint64(listHeadBytes[8:16], nodeVA)

	// Layout — keep offsets compact for the test fixture but match
	// the same shape as a real KIWI_MASTERKEY_CACHE_ENTRY.
	layout := DPAPILayout{
		NodeSize:       0x80,
		LUIDOffset:     0x10,
		KeyGUIDOffset:  0x18,
		KeySizeOffset:  0x28,
		KeyBytesOffset: 0x30,
	}

	// Build the node bytes.
	wantLUID := uint64(0x1122334455667788)
	wantGUID := [16]byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
	}
	wantKey := make([]byte, 64)
	for i := range wantKey {
		wantKey[i] = byte(i ^ 0xA5)
	}

	node := make([]byte, layout.NodeSize)
	binary.LittleEndian.PutUint64(node[0:8], listHead)  // Flink → loop back
	binary.LittleEndian.PutUint64(node[8:16], listHead) // Blink (unused)
	binary.LittleEndian.PutUint64(node[layout.LUIDOffset:layout.LUIDOffset+8], wantLUID)
	copy(node[layout.KeyGUIDOffset:layout.KeyGUIDOffset+16], wantGUID[:])
	binary.LittleEndian.PutUint32(node[layout.KeySizeOffset:layout.KeySizeOffset+4], uint32(len(wantKey)))
	copy(node[layout.KeyBytesOffset:], wantKey)

	regions := []lsassdump.MemoryRegion{
		{BaseAddress: modBase, Data: moduleBody},
		{BaseAddress: listHead, Data: listHeadBytes},
		{BaseAddress: nodeVA, Data: node},
	}
	mods := []lsassdump.Module{
		{BaseOfImage: modBase, SizeOfImage: modSize, Name: "lsasrv.dll"},
	}
	blob := buildFixture(t, mods, regions)

	r, err := openReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("openReader: %v", err)
	}

	tmpl := &Template{
		BuildMin:           19045,
		BuildMax:           19045,
		IVPattern:          []byte{0x90}, // unused
		Key3DESPattern:     []byte{0x90},
		KeyAESPattern:      []byte{0x90},
		DPAPIListPattern:   pattern,
		DPAPIListOffset:    int32(rel32At - patternOff),
		DPAPILayout:        layout,
	}
	mod := Module{Name: "lsasrv.dll", BaseOfImage: modBase, SizeOfImage: modSize}

	keys, warnings := extractDPAPI(r, mod, tmpl)
	if len(warnings) > 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	if len(keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(keys))
	}
	mk, ok := keys[wantLUID]
	if !ok {
		t.Fatalf("LUID 0x%X missing from keys map (got %v)", wantLUID, keys)
	}
	if mk.KeyGUID != wantGUID {
		t.Errorf("KeyGUID = %x, want %x", mk.KeyGUID, wantGUID)
	}
	if !bytes.Equal(mk.KeyBytes, wantKey) {
		t.Errorf("KeyBytes = %x\nwant     %x", mk.KeyBytes, wantKey)
	}
	if !mk.Found {
		t.Error("Found = false on a successful extract")
	}
}

// TestDecodeDPAPINode_OversizedKeySize covers the 1KB cap guard
// against a corrupted dump whose key-size field landed somewhere
// non-numeric.
func TestDecodeDPAPINode_OversizedKeySize(t *testing.T) {
	layout := DPAPILayout{
		NodeSize:       0x80,
		LUIDOffset:     0x10,
		KeyGUIDOffset:  0x18,
		KeySizeOffset:  0x28,
		KeyBytesOffset: 0x30,
	}
	node := make([]byte, layout.NodeSize)
	binary.LittleEndian.PutUint64(node[layout.LUIDOffset:layout.LUIDOffset+8], 0x123)
	binary.LittleEndian.PutUint32(node[layout.KeySizeOffset:layout.KeySizeOffset+4], 99999)

	mk, warn := decodeDPAPINode(node, layout)
	if warn != "" {
		t.Errorf("warn = %q, want empty (oversized = silently skip)", warn)
	}
	if mk.LUID != 0x123 {
		t.Errorf("LUID = 0x%X, want 0x123", mk.LUID)
	}
	if mk.KeyBytes != nil {
		t.Errorf("KeyBytes = %v, want nil for oversized cap", mk.KeyBytes)
	}
	if mk.Found {
		t.Error("Found = true on oversized key-size guard")
	}
}

// TestDecodeDPAPINode_KeyOverrunsNode covers the layout-arithmetic
// guard: KeyBytesOffset + KeySize > NodeSize.
func TestDecodeDPAPINode_KeyOverrunsNode(t *testing.T) {
	layout := DPAPILayout{
		NodeSize:       0x40, // tight
		LUIDOffset:     0x10,
		KeyGUIDOffset:  0x18,
		KeySizeOffset:  0x28,
		KeyBytesOffset: 0x30, // 0x30 + 64 > 0x40
	}
	node := make([]byte, layout.NodeSize)
	binary.LittleEndian.PutUint32(node[layout.KeySizeOffset:layout.KeySizeOffset+4], 64)
	_, warn := decodeDPAPINode(node, layout)
	if warn == "" {
		t.Error("expected warn on key-overrun, got empty")
	}
}

// TestMergeDPAPI_GraftsExisting confirms a master key whose LUID
// matches an existing MSV session is appended (not duplicated).
func TestMergeDPAPI_GraftsExisting(t *testing.T) {
	sessions := []LogonSession{
		{LUID: 0xAAAA, UserName: "alice", Credentials: []Credential{MSV1_0Credential{UserName: "alice", Found: true}}},
	}
	keys := map[uint64]DPAPIMasterKey{
		0xAAAA: {LUID: 0xAAAA, KeyBytes: []byte{0xDE}, Found: true},
	}
	out := mergeDPAPI(sessions, keys)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	if len(out[0].Credentials) != 2 {
		t.Fatalf("Credentials = %d, want MSV+DPAPI", len(out[0].Credentials))
	}
	if _, ok := out[0].Credentials[1].(DPAPIMasterKey); !ok {
		t.Errorf("Credentials[1] type = %T, want DPAPIMasterKey", out[0].Credentials[1])
	}
}

// TestMergeDPAPI_OrphanSurfaces verifies a DPAPI LUID with no MSV
// counterpart becomes a new LogonSession.
func TestMergeDPAPI_OrphanSurfaces(t *testing.T) {
	keys := map[uint64]DPAPIMasterKey{
		0xBBBB: {LUID: 0xBBBB, KeyBytes: []byte{0x01, 0x02}, Found: true},
	}
	out := mergeDPAPI(nil, keys)
	if len(out) != 1 || out[0].LUID != 0xBBBB {
		t.Errorf("orphan = %+v, want LUID=0xBBBB session", out)
	}
}

// TestMergeDPAPI_Empty — no DPAPI keys is a non-mutating no-op.
func TestMergeDPAPI_Empty(t *testing.T) {
	in := []LogonSession{{LUID: 0x1}}
	out := mergeDPAPI(in, nil)
	if len(out) != 1 || out[0].LUID != 0x1 {
		t.Errorf("empty keys mutated sessions: %+v", out)
	}
}

// TestHexLower covers the local lowercase-hex helper.
func TestHexLower(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, ""},
		{"single", []byte{0xAB}, "ab"},
		{"multi", []byte{0x00, 0xFF, 0xCA, 0xFE}, "00ffcafe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hexLower(tc.in); got != tc.want {
				t.Errorf("hexLower(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
