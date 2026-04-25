package lsasparse

import "testing"

// TestLiveSSPCredential_AuthPackage covers the interface contract.
func TestLiveSSPCredential_AuthPackage(t *testing.T) {
	if got := (LiveSSPCredential{}).AuthPackage(); got != "LiveSSP" {
		t.Errorf("AuthPackage = %q, want LiveSSP", got)
	}
}

// TestLiveSSPCredential_String — Domain\User:Password matrix.
func TestLiveSSPCredential_String(t *testing.T) {
	cases := []struct {
		name string
		c    LiveSSPCredential
		want string
	}{
		{"msa+pwd", LiveSSPCredential{UserName: "alice", LogonDomain: "MicrosoftAccount", Password: "p"}, `MicrosoftAccount\alice:p`},
		{"no-domain", LiveSSPCredential{UserName: "bob", Password: "x"}, `bob:x`},
		{"empty-pwd", LiveSSPCredential{UserName: "u", LogonDomain: "MSA"}, `MSA\u:`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.String(); got != tc.want {
				t.Errorf("String = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLiveSSPCredential_Wipe — password cleared.
func TestLiveSSPCredential_Wipe(t *testing.T) {
	c := &LiveSSPCredential{UserName: "alice", Password: "Hunter2", Found: true}
	c.wipe()
	if c.Password != "" || c.Found {
		t.Errorf("wipe failed: %+v", c)
	}
}

// TestExtractLiveSSP_Disabled — NodeSize=0 short-circuit.
func TestExtractLiveSSP_Disabled(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()
	tmpl := &Template{}
	creds, warnings := extractLiveSSP(nil, Module{}, tmpl, nil)
	if creds != nil || warnings != nil {
		t.Errorf("disabled returned creds=%v warnings=%v", creds, warnings)
	}
}

// TestMergeLiveSSP — graft / orphan / empty paths.
func TestMergeLiveSSP_Grafts(t *testing.T) {
	sessions := []LogonSession{
		{LUID: 0xAAAA, UserName: "alice", Credentials: []Credential{MSV1_0Credential{UserName: "alice", Found: true}}},
	}
	live := map[uint64]LiveSSPCredential{
		0xAAAA: {UserName: "alice", LogonDomain: "MSA", Password: "p", Found: true},
	}
	out := mergeLiveSSP(sessions, live)
	if len(out) != 1 || len(out[0].Credentials) != 2 {
		t.Fatalf("graft failed: %+v", out)
	}
	if _, ok := out[0].Credentials[1].(LiveSSPCredential); !ok {
		t.Errorf("Credentials[1] type = %T, want LiveSSPCredential", out[0].Credentials[1])
	}
}

func TestMergeLiveSSP_Orphan(t *testing.T) {
	live := map[uint64]LiveSSPCredential{
		0xBBBB: {UserName: "u", LogonDomain: "MSA", Password: "x", Found: true},
	}
	out := mergeLiveSSP(nil, live)
	if len(out) != 1 || out[0].LUID != 0xBBBB {
		t.Errorf("orphan = %+v", out)
	}
}

func TestMergeLiveSSP_Empty(t *testing.T) {
	in := []LogonSession{{LUID: 0x1}}
	out := mergeLiveSSP(in, nil)
	if len(out) != 1 || out[0].LUID != 0x1 {
		t.Errorf("empty mutated sessions: %+v", out)
	}
}
