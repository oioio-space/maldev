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

// TestDecodeTSPkgNode_SwapsUserNameAndDomain verifies the Microsoft
// quirk pypykatz documents: TSPkg's primary credential struct
// stores the values at swapped UNICODE_STRING slots (the "UserName"
// slot holds the domain and vice versa). Our decoder swaps them
// back so callers see the canonical user / domain pair.
//
// This is a focused unit test on decodeTSPkgNode rather than the
// full extractTSPkg walker — the AVL+pointer-chain machinery is
// covered by the avl_test.go tree-traversal tests and validated
// end-to-end against real lsass dumps via the env-gated
// TestRealDumpDiagnostics + ad-hoc parser runs.
func TestDecodeTSPkgNode_SwapsUserNameAndDomain(t *testing.T) {
	const (
		modBase   uint64 = 0x7FF800000000
		modSize          = uint32(0x1000)
		primaryVA uint64 = modBase + uint64(modSize) + 0x200
		userBuf   uint64 = modBase + uint64(modSize) + 0x300
		domBuf    uint64 = modBase + uint64(modSize) + 0x400
		pwdCipher uint64 = modBase + uint64(modSize) + 0x500
	)

	layout := TSPkgLayout{
		NodeSize:         0x90,
		LUIDOffset:       0x70,
		PrimaryPtrOffset: 0x88,
	}
	wantLUID := uint64(0xCAFEBABEDEADBEEF)

	// Encrypt a known plaintext password.
	aes, err := instantiateCipher([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("aes import: %v", err)
	}
	iv := []byte("ABCDEFGHIJKLMNOP")
	keys := &lsaKey{IV: iv, AES: aes}
	plainStr := "RDP@2026"
	plainU16 := utf16Encode(plainStr)
	plain := make([]byte, 16)
	for i, c := range plainU16 {
		binary.LittleEndian.PutUint16(plain[i*2:i*2+2], c)
	}
	cipherText := make([]byte, len(plain))
	encryptCBC(t, aes, iv, plain, cipherText)

	// Outer node: 0x90 bytes with LUID at 0x70 and pTsPrimary at 0x88.
	node := make([]byte, layout.NodeSize)
	binary.LittleEndian.PutUint64(node[layout.LUIDOffset:layout.LUIDOffset+8], wantLUID)
	binary.LittleEndian.PutUint64(node[layout.PrimaryPtrOffset:layout.PrimaryPtrOffset+8], primaryVA)

	// Inner primary credential, with the SWAPPED layout Microsoft
	// uses: the "UserName" slot at +0x00 stores the *domain*, and
	// the "Domain" slot at +0x10 stores the *username*.
	primary := make([]byte, 0x30)
	storedAtUserSlot := utf16Encode("CORP")
	binary.LittleEndian.PutUint16(primary[0x00:0x02], uint16(len(storedAtUserSlot)*2))
	binary.LittleEndian.PutUint16(primary[0x02:0x04], uint16(len(storedAtUserSlot)*2+2))
	binary.LittleEndian.PutUint64(primary[0x08:0x10], userBuf)

	storedAtDomSlot := utf16Encode("alice")
	binary.LittleEndian.PutUint16(primary[0x10:0x12], uint16(len(storedAtDomSlot)*2))
	binary.LittleEndian.PutUint16(primary[0x12:0x14], uint16(len(storedAtDomSlot)*2+2))
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
		{BaseAddress: modBase, Data: make([]byte, modSize)},
		{BaseAddress: primaryVA, Data: primary},
		{BaseAddress: userBuf, Data: utf16Region("CORP")},
		{BaseAddress: domBuf, Data: utf16Region("alice")},
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

	tmpl := &Template{TSPkgLayout: layout}
	cred, luid, warn := decodeTSPkgNode(r, node, tmpl, keys)
	if warn != "" {
		t.Errorf("decodeTSPkgNode warn = %q, want empty", warn)
	}
	if luid != wantLUID {
		t.Errorf("luid = 0x%X, want 0x%X", luid, wantLUID)
	}
	// The decoder must SWAP the slots → user "alice", domain "CORP".
	if cred.UserName != "alice" {
		t.Errorf("UserName = %q, want alice (after swap)", cred.UserName)
	}
	if cred.LogonDomain != "CORP" {
		t.Errorf("LogonDomain = %q, want CORP (after swap)", cred.LogonDomain)
	}
	if cred.Password != plainStr {
		t.Errorf("Password = %q, want %q", cred.Password, plainStr)
	}
	if !cred.Found {
		t.Error("Found = false on a successful decode")
	}
}

// TestMergeTSPkg_Grafts confirms TSPkg credentials matching an
// existing MSV LogonSession by LUID get appended (not duplicated).
func TestMergeTSPkg_Grafts(t *testing.T) {
	sessions := []LogonSession{
		{LUID: 0xAAAA, UserName: "alice", Credentials: []Credential{&MSVCredential{UserName: "alice", Found: true}}},
	}
	ts := map[uint64]*TSPkgCredential{
		0xAAAA: {UserName: "alice", Password: "RDP123", Found: true},
	}
	out := mergeTSPkg(sessions, ts)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1 (graft, not new)", len(out))
	}
	if len(out[0].Credentials) != 2 {
		t.Fatalf("Credentials = %d, want MSV+TSPkg", len(out[0].Credentials))
	}
	if _, ok := out[0].Credentials[1].(*TSPkgCredential); !ok {
		t.Errorf("Credentials[1] type = %T, want TSPkgCredential", out[0].Credentials[1])
	}
}

// TestMergeTSPkg_Orphan — TSPkg LUID with no MSV match becomes a
// new session.
func TestMergeTSPkg_Orphan(t *testing.T) {
	ts := map[uint64]*TSPkgCredential{
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
