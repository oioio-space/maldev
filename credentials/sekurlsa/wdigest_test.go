package sekurlsa

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/oioio-space/maldev/credentials/lsassdump"
)

// TestWdigestCredential_AuthPackage covers the interface contract.
func TestWdigestCredential_AuthPackage(t *testing.T) {
	if got := (WdigestCredential{}).AuthPackage(); got != "Wdigest" {
		t.Errorf("AuthPackage = %q, want Wdigest", got)
	}
}

// TestWdigestCredential_String covers the (Domain present/absent) ×
// (Password present/empty) matrix.
func TestWdigestCredential_String(t *testing.T) {
	cases := []struct {
		name string
		c    WdigestCredential
		want string
	}{
		{"domain+password", WdigestCredential{UserName: "alice", LogonDomain: "CORP", Password: "Hunter2"}, `CORP\alice:Hunter2`},
		{"no-domain", WdigestCredential{UserName: "bob", Password: "Pa$$"}, `bob:Pa$$`},
		{"empty-password", WdigestCredential{UserName: "svc", LogonDomain: "NT AUTHORITY"}, `NT AUTHORITY\svc:`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.String(); got != tc.want {
				t.Errorf("String = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestWdigestCredential_Wipe — plaintext password must be cleared.
func TestWdigestCredential_Wipe(t *testing.T) {
	c := &WdigestCredential{UserName: "alice", Password: "Hunter2", Found: true}
	c.wipe()
	if c.Password != "" {
		t.Errorf("Password = %q, want empty", c.Password)
	}
	if c.Found {
		t.Error("Found = true after wipe")
	}
	if c.UserName != "alice" {
		t.Errorf("UserName mutated by wipe: %q", c.UserName)
	}
}

// TestExtractWdigest_Disabled covers the "WdigestLayout.NodeSize == 0"
// short-circuit — a template that doesn't support Wdigest must skip
// the walker without error and without reading any module bytes.
func TestExtractWdigest_Disabled(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()

	tmpl := &Template{
		// Wdigest fields all zero — NodeSize=0 disables the walker.
	}
	creds, warnings := extractWdigest(nil, Module{}, tmpl, nil)
	if creds != nil {
		t.Errorf("creds = %v, want nil when disabled", creds)
	}
	if warnings != nil {
		t.Errorf("warnings = %v, want nil when disabled", warnings)
	}
}

// TestExtractWdigest_HappyPath builds a synthetic wdigest.dll mapping
// with one logon-session node carrying an encrypted password, walks
// the list, decrypts, and verifies the plaintext round-trips.
func TestExtractWdigest_HappyPath(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()

	const (
		modBase  uint64 = 0x7FF800000000
		modSize         = uint32(0x1000)
		listHead uint64 = modBase + uint64(modSize) + 0x000
		nodeVA   uint64 = modBase + uint64(modSize) + 0x100
		userBuf  uint64 = modBase + uint64(modSize) + 0x200
		domBuf   uint64 = modBase + uint64(modSize) + 0x300
		pwdBuf   uint64 = modBase + uint64(modSize) + 0x400
	)

	// Module body: pattern + rel32 → listHead.
	moduleBody := make([]byte, modSize)
	pattern := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	patternOff := 0x80
	copy(moduleBody[patternOff:], pattern)
	rel32At := patternOff + 4
	rel32 := int32(int64(listHead) - int64(modBase) - int64(rel32At) - 4)
	binary.LittleEndian.PutUint32(moduleBody[rel32At:rel32At+4], uint32(rel32))

	// listHead: Flink points at our node, Blink points at our node too
	// (single-entry circular list). When the walker reads listHead's
	// 8 bytes (Flink) it gets nodeVA.
	listHeadBytes := make([]byte, 16)
	binary.LittleEndian.PutUint64(listHeadBytes[0:8], nodeVA)
	binary.LittleEndian.PutUint64(listHeadBytes[8:16], nodeVA)

	// Layout we'll register: simple aligned offsets that fit a 0x80
	// byte node. Real Win10 KIWI_WDIGEST_LIST_ENTRY uses 0x28/0x38/
	// 0x48/0x58 — we use 0x10/0x20/0x30/0x40 here to keep the test
	// compact.
	layout := WdigestLayout{
		NodeSize:       0x80,
		LUIDOffset:     0x10,
		UserNameOffset: 0x20,
		DomainOffset:   0x30,
		PasswordOffset: 0x40,
	}

	// Encrypt a known plaintext with the LSA AES key. The walker calls
	// decryptLSA which picks AES on 16-byte alignment.
	var _ = "" // KDBM removed
	aes, err := instantiateCipher([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("aes import: %v", err)
	}
	iv := []byte("ABCDEFGHIJKLMNOP")
	keys := &lsaKey{IV: iv, AES: aes}

	// Plaintext: UTF-16LE "Hunter2!" padded to 16 bytes (one AES block).
	plainStr := "Hunter2!"
	plainU16 := utf16Encode(plainStr)
	plain := make([]byte, 16) // pad to one AES block
	for i, c := range plainU16 {
		binary.LittleEndian.PutUint16(plain[i*2:i*2+2], c)
	}
	cipherText := make([]byte, len(plain))
	encryptCBC(t, aes, iv, plain, cipherText)

	// Build the node bytes.
	node := make([]byte, layout.NodeSize)
	binary.LittleEndian.PutUint64(node[0:8], listHead)  // Flink → loop back
	binary.LittleEndian.PutUint64(node[8:16], listHead) // Blink (unused)
	binary.LittleEndian.PutUint64(node[layout.LUIDOffset:layout.LUIDOffset+8], 0xDEADBEEFCAFEBABE)
	// UserName UNICODE_STRING.
	user := utf16Encode("alice")
	binary.LittleEndian.PutUint16(node[layout.UserNameOffset:layout.UserNameOffset+2], uint16(len(user)*2))
	binary.LittleEndian.PutUint16(node[layout.UserNameOffset+2:layout.UserNameOffset+4], uint16(len(user)*2+2))
	binary.LittleEndian.PutUint64(node[layout.UserNameOffset+8:layout.UserNameOffset+16], userBuf)
	// Domain UNICODE_STRING.
	dom := utf16Encode("CORP")
	binary.LittleEndian.PutUint16(node[layout.DomainOffset:layout.DomainOffset+2], uint16(len(dom)*2))
	binary.LittleEndian.PutUint16(node[layout.DomainOffset+2:layout.DomainOffset+4], uint16(len(dom)*2+2))
	binary.LittleEndian.PutUint64(node[layout.DomainOffset+8:layout.DomainOffset+16], domBuf)
	// Password UNICODE_STRING — Length is the encrypted blob size, Buffer the cipher VA.
	binary.LittleEndian.PutUint16(node[layout.PasswordOffset:layout.PasswordOffset+2], uint16(len(cipherText)))
	binary.LittleEndian.PutUint16(node[layout.PasswordOffset+2:layout.PasswordOffset+4], uint16(len(cipherText)))
	binary.LittleEndian.PutUint64(node[layout.PasswordOffset+8:layout.PasswordOffset+16], pwdBuf)

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
		{BaseAddress: userBuf, Data: utf16Region("alice")},
		{BaseAddress: domBuf, Data: utf16Region("CORP")},
		{BaseAddress: pwdBuf, Data: cipherText},
	}
	mods := []lsassdump.Module{
		{BaseOfImage: modBase, SizeOfImage: modSize, Name: "wdigest.dll"},
	}
	blob := buildFixture(t, mods, regions)

	r, err := openReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("openReader: %v", err)
	}

	tmpl := &Template{
		BuildMin:             19045,
		BuildMax:             19045,
		IVPattern:            []byte{0x90}, // unused — we hand-build keys
		Key3DESPattern:       []byte{0x90},
		KeyAESPattern:        []byte{0x90},
		WdigestListPattern:   pattern,
		WdigestListOffset:    int32(rel32At - patternOff),
		WdigestLayout:        layout,
	}
	mod := Module{Name: "wdigest.dll", BaseOfImage: modBase, SizeOfImage: modSize}

	creds, warnings := extractWdigest(r, mod, tmpl, keys)

	if len(warnings) > 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	if len(creds) != 1 {
		t.Fatalf("creds = %d, want 1", len(creds))
	}
	cred, ok := creds[0xDEADBEEFCAFEBABE]
	if !ok {
		t.Fatal("LUID 0xDEADBEEFCAFEBABE missing from creds map")
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

// TestMergeWdigest_GraftsExisting confirms a Wdigest credential whose
// LUID matches an MSV session is appended to that session's
// Credentials slice (not a new session).
func TestMergeWdigest_GraftsExisting(t *testing.T) {
	sessions := []LogonSession{
		{LUID: 0xAAAA, UserName: "alice", Credentials: []Credential{&MSVCredential{UserName: "alice", Found: true}}},
	}
	wdig := map[uint64]*WdigestCredential{
		0xAAAA: {UserName: "alice", Password: "Hunter2", Found: true},
	}
	out := mergeWdigest(sessions, wdig)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1 (graft, not new)", len(out))
	}
	if len(out[0].Credentials) != 2 {
		t.Fatalf("Credentials = %d, want 2 (MSV + Wdigest)", len(out[0].Credentials))
	}
	if _, ok := out[0].Credentials[1].(*WdigestCredential); !ok {
		t.Errorf("Credentials[1] type = %T, want WdigestCredential", out[0].Credentials[1])
	}
}

// TestMergeWdigest_OrphansSurface confirms a Wdigest LUID with no MSV
// match becomes a new LogonSession instead of being silently dropped.
func TestMergeWdigest_OrphansSurface(t *testing.T) {
	wdig := map[uint64]*WdigestCredential{
		0xBBBB: {UserName: "svc", LogonDomain: "NT", Password: "x", Found: true},
	}
	out := mergeWdigest(nil, wdig)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1 (orphan surfaced)", len(out))
	}
	if out[0].LUID != 0xBBBB || out[0].UserName != "svc" {
		t.Errorf("orphan LogonSession = %+v", out[0])
	}
}

// TestMergeWdigest_Empty confirms the no-Wdigest path doesn't allocate
// or mutate.
func TestMergeWdigest_Empty(t *testing.T) {
	in := []LogonSession{{LUID: 0x1}}
	out := mergeWdigest(in, nil)
	if len(out) != 1 || out[0].LUID != 0x1 {
		t.Errorf("empty wdig mutated sessions: %+v", out)
	}
}

// TestDecodeUTF16LEBytes covers padding-tail trim + odd-byte tail.
func TestDecodeUTF16LEBytes(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, ""},
		{"plain", []byte{'H', 0, 'i', 0}, "Hi"},
		{"trailing-nul-pair", []byte{'H', 0, 'i', 0, 0, 0, 0, 0}, "Hi"},
		{"odd-byte-tail", []byte{'H', 0, 'i', 0, 0xFF}, "Hi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decodeUTF16LEBytes(tc.in); got != tc.want {
				t.Errorf("decodeUTF16LEBytes(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
