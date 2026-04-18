package srdi

import (
	"strings"
	"testing"
)

func TestArchString(t *testing.T) {
	tests := []struct {
		a    Arch
		want string
	}{
		{ArchX32, "x32"},
		{ArchX64, "x64"},
		{ArchX84, "x84"},
	}
	for _, tc := range tests {
		if got := tc.a.String(); got != tc.want {
			t.Errorf("Arch(%d).String() = %q, want %q", int(tc.a), got, tc.want)
		}
	}

	// Unknown arch falls through to Arch(%d).
	const bogus Arch = 99
	if got := bogus.String(); !strings.HasPrefix(got, "Arch(") {
		t.Errorf("unknown Arch should format as Arch(%%d), got %q", got)
	}
}

func TestModuleTypeString(t *testing.T) {
	tests := []struct {
		m    ModuleType
		want string
	}{
		{ModuleNetDLL, "NetDLL"},
		{ModuleNetEXE, "NetEXE"},
		{ModuleDLL, "DLL"},
		{ModuleEXE, "EXE"},
		{ModuleVBS, "VBS"},
		{ModuleJS, "JS"},
		{ModuleXSL, "XSL"},
	}
	for _, tc := range tests {
		if got := tc.m.String(); got != tc.want {
			t.Errorf("ModuleType(%d).String() = %q, want %q", int(tc.m), got, tc.want)
		}
	}

	const bogus ModuleType = 99
	if got := bogus.String(); !strings.HasPrefix(got, "ModuleType(") {
		t.Errorf("unknown ModuleType should format as ModuleType(%%d), got %q", got)
	}
}
