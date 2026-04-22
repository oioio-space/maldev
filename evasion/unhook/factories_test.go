//go:build windows

package unhook

import (
	"strings"
	"testing"
)

// Factory tests exercise the Technique constructors (Classic, ClassicAll,
// CommonClassic, Full, Perun) and their Name() methods. Apply() isn't called:
// that would require a real hooked ntdll and cross-process memory reads, which
// belong in the intrusive test set. The construction paths are pure Go and
// safe to run anywhere Windows compiles.

func TestClassicFactory(t *testing.T) {
	tech := Classic("NtAllocateVirtualMemory")
	if tech == nil {
		t.Fatal("Classic returned nil")
	}
	want := "unhook:Classic(NtAllocateVirtualMemory)"
	if got := tech.Name(); got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestClassicAll(t *testing.T) {
	names := []string{"NtAllocateVirtualMemory", "NtCreateThreadEx", "NtProtectVirtualMemory"}
	techs := ClassicAll(names)
	if len(techs) != len(names) {
		t.Fatalf("ClassicAll returned %d techniques, want %d", len(techs), len(names))
	}
	for i, n := range names {
		got := techs[i].Name()
		if !strings.Contains(got, n) {
			t.Errorf("techs[%d].Name() = %q, must contain %q", i, got, n)
		}
	}
}

func TestClassicAll_Empty(t *testing.T) {
	if got := ClassicAll(nil); len(got) != 0 {
		t.Errorf("ClassicAll(nil) length = %d, want 0", len(got))
	}
	if got := ClassicAll([]string{}); len(got) != 0 {
		t.Errorf("ClassicAll([]) length = %d, want 0", len(got))
	}
}

func TestCommonClassic(t *testing.T) {
	techs := CommonClassic()
	if len(techs) == 0 {
		t.Fatal("CommonClassic returned empty slice")
	}
	if len(techs) != len(CommonHookedFunctions) {
		t.Errorf("CommonClassic length = %d, want %d", len(techs), len(CommonHookedFunctions))
	}
	// Name prefixes must line up with CommonHookedFunctions entries.
	for i, n := range CommonHookedFunctions {
		if !strings.Contains(techs[i].Name(), n) {
			t.Errorf("tech[%d].Name() = %q, must contain %q", i, techs[i].Name(), n)
		}
	}
}

func TestFullFactory(t *testing.T) {
	tech := Full()
	if tech == nil {
		t.Fatal("Full returned nil")
	}
	if got := tech.Name(); got != "unhook:Full" {
		t.Errorf("Full().Name() = %q, want %q", got, "unhook:Full")
	}
}

func TestPerunFactory(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "unhook:Perun(svchost.exe)"}, // empty → default
		{"notepad.exe", "unhook:Perun(notepad.exe)"},
		{"calc.exe", "unhook:Perun(calc.exe)"},
	}
	for _, c := range cases {
		tech := Perun(c.in)
		if tech == nil {
			t.Fatalf("Perun(%q) = nil", c.in)
		}
		if got := tech.Name(); got != c.want {
			t.Errorf("Perun(%q).Name() = %q, want %q", c.in, got, c.want)
		}
	}
}
