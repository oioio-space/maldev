package lsasparse

import (
	"strings"
	"testing"
)

// TestCloudAPCredential_AuthPackage covers the interface contract.
func TestCloudAPCredential_AuthPackage(t *testing.T) {
	if got := (CloudAPCredential{}).AuthPackage(); got != "CloudAP" {
		t.Errorf("AuthPackage = %q, want CloudAP", got)
	}
}

// TestCloudAPCredential_String — UserName <AccountID> + PRT preview.
func TestCloudAPCredential_String(t *testing.T) {
	c := CloudAPCredential{
		UserName:  "Alice User",
		AccountID: "alice@contoso.onmicrosoft.com",
		PRT:       []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A},
	}
	got := c.String()
	if !strings.Contains(got, "Alice User") {
		t.Errorf("String missing user: %q", got)
	}
	if !strings.Contains(got, "alice@contoso.onmicrosoft.com") {
		t.Errorf("String missing AccountID: %q", got)
	}
	// PRT preview is the first 16 bytes hex-lowered + length annotation.
	if !strings.Contains(got, "deadbeefcafebabe") {
		t.Errorf("String missing PRT preview: %q", got)
	}
	if !strings.Contains(got, "(18b)") {
		t.Errorf("String missing PRT length annotation: %q", got)
	}
}

// TestCloudAPCredential_String_NoPRT covers the no-PRT branch.
func TestCloudAPCredential_String_NoPRT(t *testing.T) {
	c := CloudAPCredential{AccountID: "bob@example.com"}
	got := c.String()
	if got != "bob@example.com" {
		t.Errorf("String = %q, want bob@example.com", got)
	}
}

// TestCloudAPCredential_Wipe — PRT + Found cleared, UserName preserved.
func TestCloudAPCredential_Wipe(t *testing.T) {
	prt := []byte{0x01, 0x02, 0x03, 0x04}
	c := &CloudAPCredential{UserName: "alice", PRT: prt, Found: true}
	orig := prt

	c.wipe()

	if c.PRT != nil {
		t.Errorf("PRT = %v, want nil", c.PRT)
	}
	for _, b := range orig {
		if b != 0 {
			t.Errorf("original PRT buffer not zeroed: %v", orig)
			break
		}
	}
	if c.Found {
		t.Error("Found = true after wipe")
	}
	if c.UserName != "alice" {
		t.Errorf("UserName mutated by wipe: %q", c.UserName)
	}
}

// TestExtractCloudAP_Disabled — NodeSize=0 short-circuit.
func TestExtractCloudAP_Disabled(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()
	tmpl := &Template{}
	creds, warnings := extractCloudAP(nil, Module{}, tmpl)
	if creds != nil || warnings != nil {
		t.Errorf("disabled returned creds=%v warnings=%v", creds, warnings)
	}
}

// TestMergeCloudAP_Grafts — graft onto existing MSV session by LUID.
func TestMergeCloudAP_Grafts(t *testing.T) {
	sessions := []LogonSession{
		{LUID: 0xAAAA, UserName: "alice", Credentials: []Credential{MSV1_0Credential{UserName: "alice", Found: true}}},
	}
	cloud := map[uint64]CloudAPCredential{
		0xAAAA: {AccountID: "alice@x", PRT: []byte{1}, Found: true},
	}
	out := mergeCloudAP(sessions, cloud)
	if len(out) != 1 || len(out[0].Credentials) != 2 {
		t.Fatalf("graft failed: %+v", out)
	}
	if _, ok := out[0].Credentials[1].(CloudAPCredential); !ok {
		t.Errorf("Credentials[1] type = %T, want CloudAPCredential", out[0].Credentials[1])
	}
}

func TestMergeCloudAP_Orphan(t *testing.T) {
	cloud := map[uint64]CloudAPCredential{
		0xBBBB: {AccountID: "svc@az", PRT: []byte{2}, Found: true},
	}
	out := mergeCloudAP(nil, cloud)
	if len(out) != 1 || out[0].LUID != 0xBBBB {
		t.Errorf("orphan = %+v", out)
	}
}

func TestMergeCloudAP_Empty(t *testing.T) {
	in := []LogonSession{{LUID: 0x1}}
	out := mergeCloudAP(in, nil)
	if len(out) != 1 || out[0].LUID != 0x1 {
		t.Errorf("empty mutated sessions: %+v", out)
	}
}
