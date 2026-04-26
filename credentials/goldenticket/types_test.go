package goldenticket

import (
	"testing"
)

func TestEType_String(t *testing.T) {
	cases := []struct {
		etype EType
		want  string
	}{
		{ETypeRC4HMAC, "rc4-hmac"},
		{ETypeAES128CTS, "aes128-cts-hmac-sha1-96"},
		{ETypeAES256CTS, "aes256-cts-hmac-sha1-96"},
		{EType(0), "etype-unknown"},
		{EType(99), "etype-unknown"},
	}
	for _, tc := range cases {
		if got := tc.etype.String(); got != tc.want {
			t.Errorf("EType(%d).String() = %q, want %q", tc.etype, got, tc.want)
		}
	}
}

func TestEType_keyLen(t *testing.T) {
	cases := []struct {
		etype EType
		want  int
	}{
		{ETypeRC4HMAC, 16},
		{ETypeAES128CTS, 16},
		{ETypeAES256CTS, 32},
		{EType(0), 0},
	}
	for _, tc := range cases {
		if got := tc.etype.keyLen(); got != tc.want {
			t.Errorf("EType(%d).keyLen() = %d, want %d", tc.etype, got, tc.want)
		}
	}
}

func TestDefaultAdminGroups_Composition(t *testing.T) {
	want := map[uint32]bool{
		RIDDomainUsers:       true,
		RIDDomainAdmins:      true,
		RIDGroupPolicyAdmins: true,
		RIDSchemaAdmins:      true,
		RIDEnterpriseAdmins:  true,
	}
	if len(DefaultAdminGroups) != len(want) {
		t.Fatalf("DefaultAdminGroups len=%d, want %d", len(DefaultAdminGroups), len(want))
	}
	for _, rid := range DefaultAdminGroups {
		if !want[rid] {
			t.Errorf("DefaultAdminGroups contains unexpected RID %d", rid)
		}
		delete(want, rid)
	}
	if len(want) != 0 {
		t.Errorf("DefaultAdminGroups missing RIDs: %v", want)
	}
}
