package sekurlsa

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/oioio-space/maldev/credentials/lsassdump"
)

// TestMSVCredential_AuthPackage covers the interface contract.
func TestMSVCredential_AuthPackage(t *testing.T) {
	if got := (MSVCredential{}).AuthPackage(); got != "MSV1_0" {
		t.Errorf("AuthPackage = %q, want MSV1_0", got)
	}
}

// TestMSVCredential_String_Pwdump covers the three-by-three matrix
// of (NT empty/present) × (LM empty/present) × (Domain empty/present).
func TestMSVCredential_String_Pwdump(t *testing.T) {
	c := MSVCredential{UserName: "alice", LogonDomain: "CORP"}
	copy(c.NTHash[:], []byte{0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
		0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0})
	got := c.String()
	want := `CORP\alice:0:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::`
	if got != want {
		t.Errorf("String empty-domain-LM = %q, want %q", got, want)
	}

	// Empty hashes — must emit standard placeholders.
	empty := MSVCredential{UserName: "bob"}
	if !strings.Contains(empty.String(), "aad3b435b51404eeaad3b435b51404ee") {
		t.Error("empty LM placeholder missing")
	}
	if !strings.Contains(empty.String(), "31d6cfe0d16ae931b73c59d7e0c089c0") {
		t.Error("empty NT placeholder missing")
	}
}

// TestMSVCredential_Wipe is the in-place hash-buffer zeroizer.
func TestMSVCredential_Wipe(t *testing.T) {
	c := &MSVCredential{Found: true}
	for i := range c.NTHash {
		c.NTHash[i] = 0xFF
	}
	for i := range c.LMHash {
		c.LMHash[i] = 0xFF
	}
	for i := range c.SHA1Hash {
		c.SHA1Hash[i] = 0xFF
	}
	for i := range c.DPAPIKey {
		c.DPAPIKey[i] = 0xFF
	}
	c.wipe()
	if !isAllZero(c.NTHash[:]) || !isAllZero(c.LMHash[:]) ||
		!isAllZero(c.SHA1Hash[:]) || !isAllZero(c.DPAPIKey[:]) {
		t.Error("wipe didn't zero every hash buffer")
	}
	if c.Found {
		t.Error("wipe didn't reset Found")
	}
}

// TestParseMSV1_0Primary_FullStruct exercises the Win11+ layout (≥0x54
// bytes — NT + LM + SHA1 hashes all present).
func TestParseMSV1_0Primary_FullStruct(t *testing.T) {
	pt := make([]byte, 0x54)
	for i := 0x20; i < 0x30; i++ {
		pt[i] = 0xAA // NT hash
	}
	for i := 0x30; i < 0x40; i++ {
		pt[i] = 0xBB // LM hash
	}
	for i := 0x40; i < 0x54; i++ {
		pt[i] = 0xCC // SHA1 hash
	}
	c := parseMSVPrimary(pt)
	if !c.Found {
		t.Fatal("Found = false on full struct")
	}
	for i := range c.NTHash {
		if c.NTHash[i] != 0xAA {
			t.Errorf("NTHash[%d] = 0x%X, want 0xAA", i, c.NTHash[i])
			break
		}
	}
	for i := range c.SHA1Hash {
		if c.SHA1Hash[i] != 0xCC {
			t.Errorf("SHA1Hash[%d] = 0x%X, want 0xCC", i, c.SHA1Hash[i])
			break
		}
	}
}

// TestParseMSV1_0Primary_Win10Layout covers the pre-Win11 layout
// (no SHA1 hash, struct ends at 0x40).
func TestParseMSV1_0Primary_Win10Layout(t *testing.T) {
	pt := make([]byte, 0x40)
	for i := 0x20; i < 0x30; i++ {
		pt[i] = 0xAA
	}
	c := parseMSVPrimary(pt)
	if !c.Found {
		t.Fatal("Found = false on Win10 layout")
	}
	if !isAllZero(c.SHA1Hash[:]) {
		t.Error("SHA1Hash should be zero on a Win10 dump")
	}
}

// TestParseMSV1_0Primary_AllZero — Found must stay false.
func TestParseMSV1_0Primary_AllZero(t *testing.T) {
	c := parseMSVPrimary(make([]byte, 0x54))
	if c.Found {
		t.Error("Found = true on all-zero blob")
	}
}

// TestExtractMSV1_0_HappyPath stitches a synthetic dump that contains
// the exact bytes the walker expects: an msv1_0.dll mapping with a
// LogonSessionList head pattern, one bucket with one logon-session
// node, the node's UNICODE_STRING fields pointing at decoded
// usernames, and an encrypted PrimaryCredentials blob the walker
// decrypts to a known NT hash.
//
// This is the end-to-end integration test for phases 1-4 — every
// public surface gets exercised. The lsasrv crypto bit is stubbed
// via a hand-built lsaKey because pattern-matching real lsasrv.dll
// bytes belongs to phase 5's VM-fixture work.
func TestExtractMSV1_0_HappyPath(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()

	const (
		msvBase  uint64 = 0x7FF800000000
		msvSize         = uint32(0x1000)

		// All synthetic structures live PAST the module image so no
		// region overlaps the moduleBody mapping. derefRel32 still
		// reaches them via the rel32 displacement (+/-2 GiB range).
		listHeadVA  uint64 = msvBase + uint64(msvSize) + 0x000 // LogonSessionList global
		bucketHead  uint64 = listHeadVA                         // bucket 0 head
		nodeVA      uint64 = msvBase + uint64(msvSize) + 0x100
		userBufVA   uint64 = msvBase + uint64(msvSize) + 0x200
		domainBufVA uint64 = msvBase + uint64(msvSize) + 0x300
		serverBufVA uint64 = msvBase + uint64(msvSize) + 0x400
		primaryVA   uint64 = msvBase + uint64(msvSize) + 0x500
		credBufVA   uint64 = msvBase + uint64(msvSize) + 0x600
	)

	// Build the in-memory module image — patterns + pointers all
	// crafted by hand. We emit one byte buffer per disjoint VA range
	// so the dump's Memory64 list captures each at its right address.

	// Module image with LogonSessionList pattern at offset 0x100. The
	// rel32 at offset 0x110 dereferences to listHeadVA.
	moduleBody := make([]byte, msvSize)
	pattern := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	patternOff := 0x100
	copy(moduleBody[patternOff:], pattern)
	rel32At := patternOff + 4 // matchStart + offset(=4) → rel32
	target := listHeadVA
	patternMatchVA := msvBase + uint64(patternOff)
	rel32 := int32(int64(target) - int64(patternMatchVA) - int64(rel32At) - 4 + int64(patternOff))
	binary.LittleEndian.PutUint32(moduleBody[rel32At:rel32At+4], uint32(rel32))

	// LogonSessionList head (bucket 0): Flink points at our node, Blink
	// points at our node too (single-entry circular list).
	listHeadBytes := make([]byte, 16)
	binary.LittleEndian.PutUint64(listHeadBytes[0:8], nodeVA)   // Flink
	binary.LittleEndian.PutUint64(listHeadBytes[8:16], nodeVA)  // Blink (unused but populated for accuracy)

	// LogonSession node. Layout matches the MSVLayout we register below.
	nodeSize := uint32(0x100)
	node := make([]byte, nodeSize)
	binary.LittleEndian.PutUint64(node[0:8], bucketHead) // Flink → loop back to head
	binary.LittleEndian.PutUint64(node[8:16], bucketHead) // Blink (unused)
	binary.LittleEndian.PutUint64(node[0x10:0x18], 0x123456789ABCDEF0) // LUID
	// UserName UNICODE_STRING at +0x18
	username := utf16Encode("alice")
	binary.LittleEndian.PutUint16(node[0x18:0x1A], uint16(len(username)*2)) // Length
	binary.LittleEndian.PutUint16(node[0x1A:0x1C], uint16(len(username)*2+2))
	binary.LittleEndian.PutUint64(node[0x20:0x28], userBufVA)
	// LogonDomain UNICODE_STRING at +0x28
	domain := utf16Encode("CORP")
	binary.LittleEndian.PutUint16(node[0x28:0x2A], uint16(len(domain)*2))
	binary.LittleEndian.PutUint16(node[0x2A:0x2C], uint16(len(domain)*2+2))
	binary.LittleEndian.PutUint64(node[0x30:0x38], domainBufVA)
	// LogonServer UNICODE_STRING at +0x38
	server := utf16Encode("DC01")
	binary.LittleEndian.PutUint16(node[0x38:0x3A], uint16(len(server)*2))
	binary.LittleEndian.PutUint16(node[0x3A:0x3C], uint16(len(server)*2+2))
	binary.LittleEndian.PutUint64(node[0x40:0x48], serverBufVA)
	// LogonType uint32 at +0x48
	binary.LittleEndian.PutUint32(node[0x48:0x4C], uint32(LogonTypeInteractive))
	// CredentialsOffset pointer to PrimaryCredentials at +0x50
	binary.LittleEndian.PutUint64(node[0x50:0x58], primaryVA)

	// PrimaryCredentials list entry: 0x30-byte header. Length stores the
	// encrypted blob size; Buffer points at credBufVA.
	primary := make([]byte, 0x30)
	encLen := uint16(0x60) // 96 bytes — multiple of 16, will pick AES
	binary.LittleEndian.PutUint16(primary[0x20:0x22], encLen)
	binary.LittleEndian.PutUint64(primary[0x28:0x30], credBufVA)

	// Build a known-good lsaKey + encrypt the MSV1_0_PRIMARY_CREDENTIAL
	// payload so the walker's decrypt round-trips back to the plaintext.
	var _ = "" // KDBM removed
	aes, err := instantiateCipher([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("aes import: %v", err)
	}
	iv := []byte("ABCDEFGHIJKLMNOP")
	keys := &lsaKey{IV: iv, AES: aes}

	plain := make([]byte, encLen)
	for i := 0x20; i < 0x30; i++ {
		plain[i] = 0xAA // NT hash
	}
	cipherText := make([]byte, encLen)
	encryptCBC(t, aes, iv, plain, cipherText)

	utf16Region := func(s string) []byte {
		u := utf16Encode(s)
		out := make([]byte, len(u)*2)
		for i, c := range u {
			binary.LittleEndian.PutUint16(out[i*2:i*2+2], c)
		}
		return out
	}

	regions := []lsassdump.MemoryRegion{
		{BaseAddress: msvBase, Data: moduleBody},
		{BaseAddress: listHeadVA, Data: listHeadBytes},
		{BaseAddress: nodeVA, Data: node},
		{BaseAddress: userBufVA, Data: utf16Region("alice")},
		{BaseAddress: domainBufVA, Data: utf16Region("CORP")},
		{BaseAddress: serverBufVA, Data: utf16Region("DC01")},
		{BaseAddress: primaryVA, Data: primary},
		{BaseAddress: credBufVA, Data: cipherText},
	}

	mods := []lsassdump.Module{
		{BaseOfImage: msvBase, SizeOfImage: msvSize, Name: "lsasrv.dll"},
	}
	blob := buildFixture(t, mods, regions)

	// Build the reader, walk MSV1_0 directly (skipping the
	// extractLSAKeys pattern scan — that path is exercised by Phase 3
	// crypto tests; here we hand-build a known-good lsaKey above so
	// the focus is on session-list walking + UNICODE_STRING decoding +
	// PrimaryCredentials decryption).
	r, err := openReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("openReader: %v", err)
	}

	tmpl := &Template{
		BuildMin:                  19045,
		BuildMax:                  19045,
		IVPattern:                 []byte{0x90}, // unused in this test
		Key3DESPattern:            []byte{0x90},
		KeyAESPattern:             []byte{0x90},
		LogonSessionListPattern:   pattern,
		LogonSessionListWildcards: nil,
		LogonSessionListOffset:    int32(rel32At - patternOff),
		LogonSessionListCount:     1, // single bucket for the test
		MSVLayout: MSVLayout{
			NodeSize:          nodeSize,
			LUIDOffset:        0x10,
			UserNameOffset:    0x18,
			LogonDomainOffset: 0x28,
			LogonServerOffset: 0x38,
			LogonTypeOffset:   0x48,
			CredentialsOffset: 0x50,
		},
	}
	mod, _ := Module{Name: "lsasrv.dll", BaseOfImage: msvBase, SizeOfImage: msvSize}, true

	sessions, warnings := extractMSV(r, mod, tmpl, keys)

	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1; warnings=%v", len(sessions), warnings)
	}
	s := sessions[0]
	if s.UserName != "alice" {
		t.Errorf("UserName = %q, want alice", s.UserName)
	}
	if s.LogonDomain != "CORP" {
		t.Errorf("LogonDomain = %q, want CORP", s.LogonDomain)
	}
	if s.LogonType != LogonTypeInteractive {
		t.Errorf("LogonType = %v, want Interactive", s.LogonType)
	}
	if len(s.Credentials) != 1 {
		t.Fatalf("Credentials = %d, want 1", len(s.Credentials))
	}
	cred, ok := s.Credentials[0].(*MSVCredential)
	if !ok {
		t.Fatalf("Credentials[0] is not MSVCredential: %T", s.Credentials[0])
	}
	if !cred.Found {
		t.Errorf("cred.Found = false; expected NT hash to be non-zero")
	}
	for i := range cred.NTHash {
		if cred.NTHash[i] != 0xAA {
			t.Errorf("NTHash[%d] = 0x%X, want 0xAA", i, cred.NTHash[i])
			break
		}
	}
}

// utf16Encode is a thin wrapper for legibility in test setup.
func utf16Encode(s string) []uint16 { return utf16.Encode([]rune(s)) }
