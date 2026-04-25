package sekurlsa

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/oioio-space/maldev/credentials/lsassdump"
)

// TestCredManCredential_AuthPackage covers the interface contract.
func TestCredManCredential_AuthPackage(t *testing.T) {
	if got := (CredManCredential{}).AuthPackage(); got != "CredMan" {
		t.Errorf("AuthPackage = %q, want CredMan", got)
	}
}

// TestCredManCredential_String — resource | user:password format,
// with and without the resource field populated.
func TestCredManCredential_String(t *testing.T) {
	cases := []struct {
		name string
		c    CredManCredential
		want string
	}{
		{
			"with-resource",
			CredManCredential{UserName: "alice", LogonDomain: "CORP", Password: "Hunter2", ResourceName: "TERMSRV/dc01.corp.local"},
			`TERMSRV/dc01.corp.local | CORP\alice:Hunter2`,
		},
		{
			"no-resource",
			CredManCredential{UserName: "bob", Password: "p"},
			`bob:p`,
		},
		{
			"resource-no-domain",
			CredManCredential{UserName: "u", Password: "p", ResourceName: "git:https://github.com/x"},
			`git:https://github.com/x | u:p`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.String(); got != tc.want {
				t.Errorf("String = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCredManCredential_Wipe — plaintext password cleared.
func TestCredManCredential_Wipe(t *testing.T) {
	c := &CredManCredential{UserName: "alice", Password: "Hunter2", Found: true}
	c.wipe()
	if c.Password != "" || c.Found {
		t.Errorf("wipe failed: %+v", c)
	}
	if c.UserName != "alice" {
		t.Errorf("UserName mutated by wipe: %q", c.UserName)
	}
}

// TestExtractCredMan_DisabledLayout — NodeSize=0 short-circuit.
func TestExtractCredMan_DisabledLayout(t *testing.T) {
	creds, warn := extractCredMan(nil, 0xDEADBEEF, CredManLayout{}, nil)
	if creds != nil || warn != "" {
		t.Errorf("disabled-layout returned creds=%v warn=%q", creds, warn)
	}
}

// TestExtractCredMan_NilHead — listHeadPtr=0 short-circuit.
func TestExtractCredMan_NilHead(t *testing.T) {
	creds, warn := extractCredMan(nil, 0, CredManLayout{NodeSize: 0x80}, nil)
	if creds != nil || warn != "" {
		t.Errorf("nil-head returned creds=%v warn=%q", creds, warn)
	}
}

// TestExtractCredMan_HappyPath builds a synthetic CredMan list with
// one entry: ResourceName="TERMSRV/dc01" + UserName="alice" +
// Domain="CORP" + Password="Hunter2" (encrypted), walks it, and
// verifies the round-trip.
func TestExtractCredMan_HappyPath(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()

	const (
		modBase    uint64 = 0x7FF800000000
		modSize           = uint32(0x1000)
		listHead   uint64 = modBase + uint64(modSize) + 0x000
		nodeVA     uint64 = modBase + uint64(modSize) + 0x100
		userBuf    uint64 = modBase + uint64(modSize) + 0x200
		domBuf     uint64 = modBase + uint64(modSize) + 0x300
		resBuf     uint64 = modBase + uint64(modSize) + 0x400
		pwdCipher  uint64 = modBase + uint64(modSize) + 0x500
	)

	layout := CredManLayout{
		NodeSize:           0x80,
		UserNameOffset:     0x18,
		LogonDomainOffset:  0x28,
		PasswordOffset:     0x38,
		ResourceNameOffset: 0x48,
	}

	listHeadBytes := make([]byte, 16)
	binary.LittleEndian.PutUint64(listHeadBytes[0:8], nodeVA)
	binary.LittleEndian.PutUint64(listHeadBytes[8:16], nodeVA)

	// Encrypt password.
	keyBlob := buildKDBM(t, []byte("0123456789abcdef"))
	aes, err := parseBCryptKeyDataBlob(keyBlob)
	if err != nil {
		t.Fatalf("aes import: %v", err)
	}
	iv := []byte("ABCDEFGHIJKLMNOP")
	keys := &lsaKey{IV: iv, AES: aes}

	plainStr := "Hunter2!"
	plainU16 := utf16Encode(plainStr)
	plain := make([]byte, 16)
	for i, c := range plainU16 {
		binary.LittleEndian.PutUint16(plain[i*2:i*2+2], c)
	}
	cipherText := make([]byte, len(plain))
	encryptCBC(t, aes, iv, plain, cipherText)

	// Build the node.
	node := make([]byte, layout.NodeSize)
	binary.LittleEndian.PutUint64(node[0:8], listHead)  // Flink → loop back
	binary.LittleEndian.PutUint64(node[8:16], listHead) // Blink

	user := utf16Encode("alice")
	binary.LittleEndian.PutUint16(node[layout.UserNameOffset:layout.UserNameOffset+2], uint16(len(user)*2))
	binary.LittleEndian.PutUint16(node[layout.UserNameOffset+2:layout.UserNameOffset+4], uint16(len(user)*2+2))
	binary.LittleEndian.PutUint64(node[layout.UserNameOffset+8:layout.UserNameOffset+16], userBuf)

	dom := utf16Encode("CORP")
	binary.LittleEndian.PutUint16(node[layout.LogonDomainOffset:layout.LogonDomainOffset+2], uint16(len(dom)*2))
	binary.LittleEndian.PutUint16(node[layout.LogonDomainOffset+2:layout.LogonDomainOffset+4], uint16(len(dom)*2+2))
	binary.LittleEndian.PutUint64(node[layout.LogonDomainOffset+8:layout.LogonDomainOffset+16], domBuf)

	binary.LittleEndian.PutUint16(node[layout.PasswordOffset:layout.PasswordOffset+2], uint16(len(cipherText)))
	binary.LittleEndian.PutUint16(node[layout.PasswordOffset+2:layout.PasswordOffset+4], uint16(len(cipherText)))
	binary.LittleEndian.PutUint64(node[layout.PasswordOffset+8:layout.PasswordOffset+16], pwdCipher)

	res := utf16Encode("TERMSRV/dc01")
	binary.LittleEndian.PutUint16(node[layout.ResourceNameOffset:layout.ResourceNameOffset+2], uint16(len(res)*2))
	binary.LittleEndian.PutUint16(node[layout.ResourceNameOffset+2:layout.ResourceNameOffset+4], uint16(len(res)*2+2))
	binary.LittleEndian.PutUint64(node[layout.ResourceNameOffset+8:layout.ResourceNameOffset+16], resBuf)

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
		{BaseAddress: listHead, Data: listHeadBytes},
		{BaseAddress: nodeVA, Data: node},
		{BaseAddress: userBuf, Data: utf16Region("alice")},
		{BaseAddress: domBuf, Data: utf16Region("CORP")},
		{BaseAddress: resBuf, Data: utf16Region("TERMSRV/dc01")},
		{BaseAddress: pwdCipher, Data: cipherText},
	}
	mods := []lsassdump.Module{
		{BaseOfImage: modBase, SizeOfImage: modSize, Name: "lsasrv.dll"},
	}
	blob := buildFixture(t, mods, regions)

	r, err := openReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("openReader: %v", err)
	}

	creds, warn := extractCredMan(r, listHead, layout, keys)
	if warn != "" {
		t.Errorf("warn = %q, want empty", warn)
	}
	if len(creds) != 1 {
		t.Fatalf("creds = %d, want 1", len(creds))
	}
	c := creds[0]
	if c.UserName != "alice" {
		t.Errorf("UserName = %q, want alice", c.UserName)
	}
	if c.LogonDomain != "CORP" {
		t.Errorf("LogonDomain = %q, want CORP", c.LogonDomain)
	}
	if c.Password != plainStr {
		t.Errorf("Password = %q, want %q", c.Password, plainStr)
	}
	if c.ResourceName != "TERMSRV/dc01" {
		t.Errorf("ResourceName = %q, want TERMSRV/dc01", c.ResourceName)
	}
	if !c.Found {
		t.Error("Found = false on a successful CredMan extract")
	}
}

// TestReadUnicodeStringIfFits — bounds-check guard against a layout
// whose offset would extend past NodeSize.
func TestReadUnicodeStringIfFits(t *testing.T) {
	node := make([]byte, 0x40)
	cases := []struct {
		name     string
		offset   uint32
		nodeSize uint32
		want     string
	}{
		{"zero offset → empty", 0, 0x40, ""},
		{"offset past end", 0x40, 0x40, ""},
		{"offset+16 past end", 0x35, 0x40, ""}, // 0x35+16 = 0x45 > 0x40
		{"in-bounds → empty (zero ustring)", 0x10, 0x40, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := readUnicodeStringIfFits(nil, node, tc.offset, tc.nodeSize); got != tc.want {
				t.Errorf("readUnicodeStringIfFits = %q, want %q", got, tc.want)
			}
		})
	}
}
