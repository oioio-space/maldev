package sekurlsa

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/oioio-space/maldev/credentials/lsassdump"
)

// TestTSPkgCredential_AuthPackage covers the interface contract.
func TestTSPkgCredential_AuthPackage(t *testing.T) {
	if got := (TSPkgCredential{}).AuthPackage(); got != "TSPkg" {
		t.Errorf("AuthPackage = %q, want TSPkg", got)
	}
}

// TestTSPkgCredential_String covers the (Domain present/absent) ×
// (Password present/empty) matrix.
func TestTSPkgCredential_String(t *testing.T) {
	cases := []struct {
		name string
		c    TSPkgCredential
		want string
	}{
		{"domain+password", TSPkgCredential{UserName: "alice", LogonDomain: "CORP", Password: "Hunter2"}, `CORP\alice:Hunter2`},
		{"no-domain", TSPkgCredential{UserName: "bob", Password: "Pa$$"}, `bob:Pa$$`},
		{"empty-password", TSPkgCredential{UserName: "svc", LogonDomain: "NT AUTHORITY"}, `NT AUTHORITY\svc:`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.String(); got != tc.want {
				t.Errorf("String = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTSPkgCredential_Wipe — plaintext password must be cleared.
func TestTSPkgCredential_Wipe(t *testing.T) {
	c := &TSPkgCredential{UserName: "alice", Password: "Hunter2", Found: true}
	c.wipe()
	if c.Password != "" || c.Found {
		t.Errorf("wipe failed: %+v", c)
	}
	if c.UserName != "alice" {
		t.Errorf("UserName mutated by wipe: %q", c.UserName)
	}
}

// TestExtractTSPkg_Disabled — TSPkgLayout.NodeSize == 0 must skip
// the walker without error and without reading any module bytes.
func TestExtractTSPkg_Disabled(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()
	tmpl := &Template{}
	creds, warnings := extractTSPkg(nil, Module{}, tmpl, nil)
	if creds != nil {
		t.Errorf("creds = %v, want nil when disabled", creds)
	}
	if warnings != nil {
		t.Errorf("warnings = %v, want nil when disabled", warnings)
	}
}

// TestExtractTSPkg_HappyPath builds a synthetic tspkg.dll mapping
// with one logon-session node carrying a pointer to a primary
// credential struct with username/domain/encrypted-password,
// walks the list, and verifies the plaintext round-trips.
func TestExtractTSPkg_HappyPath(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()

	const (
		modBase    uint64 = 0x7FF800000000
		modSize           = uint32(0x1000)
		listHead   uint64 = modBase + uint64(modSize) + 0x000
		nodeVA     uint64 = modBase + uint64(modSize) + 0x100
		primaryVA  uint64 = modBase + uint64(modSize) + 0x200
		userBuf    uint64 = modBase + uint64(modSize) + 0x300
		domBuf     uint64 = modBase + uint64(modSize) + 0x400
		pwdCipher  uint64 = modBase + uint64(modSize) + 0x500
	)

	// Module body: pattern + rel32 → listHead.
	moduleBody := make([]byte, modSize)
	pattern := []byte{0xCA, 0xFE, 0xD0, 0x0D}
	patternOff := 0x80
	copy(moduleBody[patternOff:], pattern)
	rel32At := patternOff + 4
	rel32 := int32(int64(listHead) - int64(modBase) - int64(rel32At) - 4)
	binary.LittleEndian.PutUint32(moduleBody[rel32At:rel32At+4], uint32(rel32))

	// Circular single-entry list head.
	listHeadBytes := make([]byte, 16)
	binary.LittleEndian.PutUint64(listHeadBytes[0:8], nodeVA)
	binary.LittleEndian.PutUint64(listHeadBytes[8:16], nodeVA)

	// Outer node layout — KIWI_TS_CREDENTIAL.
	layout := TSPkgLayout{
		NodeSize:         0x20,
		LUIDOffset:       0x10,
		PrimaryPtrOffset: 0x18,
	}
	wantLUID := uint64(0xCAFEBABEDEADBEEF)
	node := make([]byte, layout.NodeSize)
	binary.LittleEndian.PutUint64(node[0:8], listHead)  // Flink → loop back
	binary.LittleEndian.PutUint64(node[8:16], listHead) // Blink (unused)
	binary.LittleEndian.PutUint64(node[layout.LUIDOffset:layout.LUIDOffset+8], wantLUID)
	binary.LittleEndian.PutUint64(node[layout.PrimaryPtrOffset:layout.PrimaryPtrOffset+8], primaryVA)

	// Encrypt the plaintext password with a known LSA AES key.
	keyBlob := buildKDBM(t, []byte("0123456789abcdef"))
	aes, err := parseBCryptKeyDataBlob(keyBlob)
	if err != nil {
		t.Fatalf("aes import: %v", err)
	}
	iv := []byte("ABCDEFGHIJKLMNOP")
	keys := &lsaKey{IV: iv, AES: aes}

	plainStr := "RDP@2026"
	plainU16 := utf16Encode(plainStr)
	plain := make([]byte, 16) // pad to 1 AES block
	for i, c := range plainU16 {
		binary.LittleEndian.PutUint16(plain[i*2:i*2+2], c)
	}
	cipherText := make([]byte, len(plain))
	encryptCBC(t, aes, iv, plain, cipherText)

	// Inner primary credential: 0x30 bytes (UserName 0x00, Domain 0x10, Password 0x20).
	primary := make([]byte, 0x30)
	user := utf16Encode("alice")
	binary.LittleEndian.PutUint16(primary[0x00:0x02], uint16(len(user)*2))
	binary.LittleEndian.PutUint16(primary[0x02:0x04], uint16(len(user)*2+2))
	binary.LittleEndian.PutUint64(primary[0x08:0x10], userBuf)

	dom := utf16Encode("CORP")
	binary.LittleEndian.PutUint16(primary[0x10:0x12], uint16(len(dom)*2))
	binary.LittleEndian.PutUint16(primary[0x12:0x14], uint16(len(dom)*2+2))
	binary.LittleEndian.PutUint64(primary[0x18:0x20], domBuf)

	binary.LittleEndian.PutUint16(primary[0x20:0x22], uint16(len(cipherText)))
	binary.LittleEndian.PutUint16(primary[0x22:0x24], uint16(len(cipherText)))
	binary.LittleEndian.PutUint64(primary[0x28:0x30], pwdCipher)

	utf16Region := func(s string) []byte {
		u := utf16Encode(s)
		out := make([]byte, len(u)*2)
		for i, c := range u {
			binary.LittleEndian.PutUint16(out[i*2:i*2+2], c)
		}
		return out
	}

	regions := []lsassdump.MemoryRegion{
		{BaseAddress: modBase, Data: moduleBody},
		{BaseAddress: listHead, Data: listHeadBytes},
		{BaseAddress: nodeVA, Data: node},
		{BaseAddress: primaryVA, Data: primary},
		{BaseAddress: userBuf, Data: utf16Region("alice")},
		{BaseAddress: domBuf, Data: utf16Region("CORP")},
		{BaseAddress: pwdCipher, Data: cipherText},
	}
	mods := []lsassdump.Module{
		{BaseOfImage: modBase, SizeOfImage: modSize, Name: "tspkg.dll"},
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
		TSPkgListPattern:   pattern,
		TSPkgListOffset:    int32(rel32At - patternOff),
		TSPkgLayout:        layout,
	}
	mod := Module{Name: "tspkg.dll", BaseOfImage: modBase, SizeOfImage: modSize}

	creds, warnings := extractTSPkg(r, mod, tmpl, keys)
	if len(warnings) > 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	if len(creds) != 1 {
		t.Fatalf("creds = %d, want 1", len(creds))
	}
	cred, ok := creds[wantLUID]
	if !ok {
		t.Fatalf("LUID 0x%X missing from creds map", wantLUID)
	}
	if cred.UserName != "alice" {
		t.Errorf("UserName = %q, want alice", cred.UserName)
	}
	if cred.LogonDomain != "CORP" {
		t.Errorf("LogonDomain = %q, want CORP", cred.LogonDomain)
	}
	if cred.Password != plainStr {
		t.Errorf("Password = %q, want %q", cred.Password, plainStr)
	}
	if !cred.Found {
		t.Error("Found = false on a successful decrypt")
	}
}

// TestMergeTSPkg_Grafts confirms TSPkg credentials matching an
// existing MSV LogonSession by LUID get appended (not duplicated).
func TestMergeTSPkg_Grafts(t *testing.T) {
	sessions := []LogonSession{
		{LUID: 0xAAAA, UserName: "alice", Credentials: []Credential{MSV1_0Credential{UserName: "alice", Found: true}}},
	}
	ts := map[uint64]TSPkgCredential{
		0xAAAA: {UserName: "alice", Password: "RDP123", Found: true},
	}
	out := mergeTSPkg(sessions, ts)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1 (graft, not new)", len(out))
	}
	if len(out[0].Credentials) != 2 {
		t.Fatalf("Credentials = %d, want MSV+TSPkg", len(out[0].Credentials))
	}
	if _, ok := out[0].Credentials[1].(TSPkgCredential); !ok {
		t.Errorf("Credentials[1] type = %T, want TSPkgCredential", out[0].Credentials[1])
	}
}

// TestMergeTSPkg_Orphan — TSPkg LUID with no MSV match becomes a
// new session.
func TestMergeTSPkg_Orphan(t *testing.T) {
	ts := map[uint64]TSPkgCredential{
		0xBBBB: {UserName: "rdpuser", Password: "x", Found: true},
	}
	out := mergeTSPkg(nil, ts)
	if len(out) != 1 || out[0].LUID != 0xBBBB || out[0].UserName != "rdpuser" {
		t.Errorf("orphan = %+v", out)
	}
}

// TestMergeTSPkg_Empty — non-mutating no-op.
func TestMergeTSPkg_Empty(t *testing.T) {
	in := []LogonSession{{LUID: 0x1}}
	out := mergeTSPkg(in, nil)
	if len(out) != 1 || out[0].LUID != 0x1 {
		t.Errorf("empty ts mutated sessions: %+v", out)
	}
}
