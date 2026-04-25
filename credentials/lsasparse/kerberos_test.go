package lsasparse

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/oioio-space/maldev/credentials/lsassdump"
)

// TestKerberosCredential_AuthPackage covers the interface contract.
func TestKerberosCredential_AuthPackage(t *testing.T) {
	if got := (KerberosCredential{}).AuthPackage(); got != "Kerberos" {
		t.Errorf("AuthPackage = %q, want Kerberos", got)
	}
}

// TestKerberosCredential_String covers the (Domain present/absent) ×
// (ticket-count) matrix.
func TestKerberosCredential_String(t *testing.T) {
	cases := []struct {
		name string
		c    KerberosCredential
		want string
	}{
		{
			"domain+pwd+2tickets",
			KerberosCredential{UserName: "alice", LogonDomain: "CORP", Password: "Hunter2", Tickets: []KerberosTicket{{}, {}}},
			`CORP\alice:Hunter2 [2 ticket(s)]`,
		},
		{
			"no-domain-no-password-no-tickets",
			KerberosCredential{UserName: "anonymous"},
			`anonymous: [0 ticket(s)]`,
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

// TestKerberosCredential_Wipe — password + every ticket buffer
// must be zeroed.
func TestKerberosCredential_Wipe(t *testing.T) {
	t1Buf := []byte{0x11, 0x22, 0x33}
	t2Buf := []byte{0xAA, 0xBB}
	c := &KerberosCredential{
		UserName: "alice",
		Password: "Hunter2",
		Tickets: []KerberosTicket{
			{ServiceName: "krbtgt", Buffer: t1Buf},
			{ServiceName: "ldap", Buffer: t2Buf},
		},
		Found: true,
	}
	// Capture original buffer slices to confirm they were zeroed.
	orig1 := t1Buf
	orig2 := t2Buf

	c.wipe()

	if c.Password != "" || c.Found {
		t.Errorf("wipe failed primary fields: %+v", c)
	}
	if c.Tickets != nil {
		t.Errorf("Tickets = %v, want nil", c.Tickets)
	}
	for _, b := range orig1 {
		if b != 0 {
			t.Errorf("ticket1 buffer not zeroed: %v", orig1)
			break
		}
	}
	for _, b := range orig2 {
		if b != 0 {
			t.Errorf("ticket2 buffer not zeroed: %v", orig2)
			break
		}
	}
}

// TestExtractKerberos_Disabled — KerberosLayout.NodeSize == 0 must
// skip the walker.
func TestExtractKerberos_Disabled(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()
	tmpl := &Template{}
	creds, warnings := extractKerberos(nil, Module{}, tmpl, nil)
	if creds != nil || warnings != nil {
		t.Errorf("disabled path returned creds=%v warnings=%v", creds, warnings)
	}
}

// TestReadExternalName covers the multi-component name decoder
// (e.g., a service principal name "krbtgt/CORP.LOCAL"). Synthetic
// fixture: build a KIWI_KERBEROS_EXTERNAL_NAME with NameCount=2 and
// two UNICODE_STRINGs whose Buffers point at separate UTF-16 strings.
func TestReadExternalName(t *testing.T) {
	const (
		modBase   uint64 = 0x7FF800000000
		modSize          = uint32(0x1000)
		extName   uint64 = modBase + uint64(modSize)
		buf1      uint64 = modBase + uint64(modSize) + 0x100
		buf2      uint64 = modBase + uint64(modSize) + 0x200
	)

	utf16Region := func(s string) []byte {
		u := utf16Encode(s)
		out := make([]byte, len(u)*2)
		for i, c := range u {
			binary.LittleEndian.PutUint16(out[i*2:i*2+2], c)
		}
		return out
	}

	// External-name struct: 8-byte header + two 16-byte UNICODE_STRINGs.
	name1 := utf16Encode("krbtgt")
	name2 := utf16Encode("CORP.LOCAL")
	ext := make([]byte, 8+2*16)
	binary.LittleEndian.PutUint16(ext[0:2], 1) // NameType
	binary.LittleEndian.PutUint16(ext[4:6], 2) // NameCount
	// First UNICODE_STRING at +8.
	binary.LittleEndian.PutUint16(ext[8:10], uint16(len(name1)*2))
	binary.LittleEndian.PutUint16(ext[10:12], uint16(len(name1)*2+2))
	binary.LittleEndian.PutUint64(ext[16:24], buf1)
	// Second UNICODE_STRING at +24.
	binary.LittleEndian.PutUint16(ext[24:26], uint16(len(name2)*2))
	binary.LittleEndian.PutUint16(ext[26:28], uint16(len(name2)*2+2))
	binary.LittleEndian.PutUint64(ext[32:40], buf2)

	regions := []lsassdump.MemoryRegion{
		{BaseAddress: modBase, Data: make([]byte, modSize)},
		{BaseAddress: extName, Data: ext},
		{BaseAddress: buf1, Data: utf16Region("krbtgt")},
		{BaseAddress: buf2, Data: utf16Region("CORP.LOCAL")},
	}
	mods := []lsassdump.Module{
		{BaseOfImage: modBase, SizeOfImage: modSize, Name: "kerberos.dll"},
	}
	blob := buildFixture(t, mods, regions)

	r, err := openReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("openReader: %v", err)
	}

	got := readExternalName(r, extName)
	want := "krbtgt/CORP.LOCAL"
	if got != want {
		t.Errorf("readExternalName = %q, want %q", got, want)
	}

	// Nil pointer → empty string.
	if got := readExternalName(r, 0); got != "" {
		t.Errorf("readExternalName(0) = %q, want empty", got)
	}
}

// TestJoinNonEmpty covers the local helper.
func TestJoinNonEmpty(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "b"}, "a/b"},
		{[]string{"a", "", "b"}, "a/b"},
		{[]string{"", "", ""}, ""},
	}
	for _, tc := range cases {
		if got := joinNonEmpty(tc.in, "/"); got != tc.want {
			t.Errorf("joinNonEmpty(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMergeKerberos — graft / orphan / empty paths mirroring the
// other merge tests.
func TestMergeKerberos_Grafts(t *testing.T) {
	sessions := []LogonSession{
		{LUID: 0xAAAA, UserName: "alice", Credentials: []Credential{MSV1_0Credential{UserName: "alice", Found: true}}},
	}
	kerb := map[uint64]KerberosCredential{
		0xAAAA: {UserName: "alice", Password: "p", Found: true},
	}
	out := mergeKerberos(sessions, kerb)
	if len(out) != 1 || len(out[0].Credentials) != 2 {
		t.Fatalf("graft failed: %+v", out)
	}
	if _, ok := out[0].Credentials[1].(KerberosCredential); !ok {
		t.Errorf("Credentials[1] type = %T, want KerberosCredential", out[0].Credentials[1])
	}
}

func TestMergeKerberos_Orphan(t *testing.T) {
	kerb := map[uint64]KerberosCredential{
		0xBBBB: {UserName: "svc", Password: "x", Found: true},
	}
	out := mergeKerberos(nil, kerb)
	if len(out) != 1 || out[0].LUID != 0xBBBB || out[0].UserName != "svc" {
		t.Errorf("orphan = %+v", out)
	}
}

func TestMergeKerberos_Empty(t *testing.T) {
	in := []LogonSession{{LUID: 0x1}}
	out := mergeKerberos(in, nil)
	if len(out) != 1 || out[0].LUID != 0x1 {
		t.Errorf("empty kerb mutated sessions: %+v", out)
	}
}
