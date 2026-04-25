package sekurlsa

import (
	"bytes"
	"testing"

	"github.com/oioio-space/maldev/credentials/lsassdump"
)

// TestModule_ByName_FoundCaseInsensitive matches by basename
// case-insensitively — pypykatz dumps sometimes contain
// "LSASRV.DLL" upper, real Windows paths are mixed-case. The
// parser must not care.
func TestModule_ByName_FoundCaseInsensitive(t *testing.T) {
	mods := []lsassdump.Module{
		{BaseOfImage: 0x7FF800000000, SizeOfImage: 0x100000, Name: "LSASRV.DLL"},
		{BaseOfImage: 0x7FF801000000, SizeOfImage: 0x080000, Name: "msv1_0.dll"},
	}
	blob := buildFixture(t, mods, nil)
	res, _ := Parse(bytes.NewReader(blob), int64(len(blob)))
	// Parse returns ErrUnsupportedBuild without templates, but still
	// fills in Modules — that's exactly the path module tests cover.
	if res == nil {
		t.Fatal("Parse: res == nil (want partial Result with Modules populated)")
	}

	for _, query := range []string{"lsasrv.dll", "LSASRV.DLL", "LsaSrv.Dll"} {
		m, ok := res.ModuleByName(query)
		if !ok {
			t.Errorf("ModuleByName(%q) not found", query)
			continue
		}
		if m.BaseOfImage != 0x7FF800000000 {
			t.Errorf("ModuleByName(%q).Base = 0x%X, want 0x7FF800000000", query, m.BaseOfImage)
		}
	}
}

// TestModule_ByName_FullPath is the regression test for v0.30.0:
// real Windows dumps store full module paths
// (`C:\Windows\system32\lsasrv.dll`) in MODULE_LIST, and the matcher
// must reduce both sides to the basename so callers can pass the
// short name.
func TestModule_ByName_FullPath(t *testing.T) {
	mods := []lsassdump.Module{
		{BaseOfImage: 0x7FF800000000, SizeOfImage: 0x100000, Name: `C:\Windows\system32\lsasrv.dll`},
		{BaseOfImage: 0x7FF801000000, SizeOfImage: 0x080000, Name: `C:\Windows\system32\msv1_0.DLL`},
		{BaseOfImage: 0x7FF802000000, SizeOfImage: 0x0A0000, Name: `C:\Windows\System32\kerberos.DLL`},
	}
	blob := buildFixture(t, mods, nil)
	res, _ := Parse(bytes.NewReader(blob), int64(len(blob)))
	if res == nil {
		t.Fatal("Parse: res == nil")
	}
	for _, q := range []string{"lsasrv.dll", "MSV1_0.DLL", "KERBEROS.dll"} {
		if _, ok := res.ModuleByName(q); !ok {
			t.Errorf("ModuleByName(%q) not found", q)
		}
	}
	// Caller can also pass the full path verbatim.
	if _, ok := res.ModuleByName(`C:\Windows\system32\lsasrv.dll`); !ok {
		t.Error("ModuleByName(full path) not found")
	}
}

// TestBasename covers the path-segment helper.
func TestBasename(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"lsasrv.dll", "lsasrv.dll"},
		{`C:\Windows\system32\lsasrv.dll`, "lsasrv.dll"},
		{`C:/Windows/system32/lsasrv.dll`, "lsasrv.dll"},
		{`/var/cache/lsass.dmp`, "lsass.dmp"},
		{`mixed\slashes/path/lsasrv.DLL`, "lsasrv.DLL"},
	}
	for _, c := range cases {
		if got := basename(c.in); got != c.want {
			t.Errorf("basename(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestModule_ByName_NotFound is the negative path — a missing
// module returns (zero, false), never an error.
func TestModule_ByName_NotFound(t *testing.T) {
	mods := []lsassdump.Module{
		{BaseOfImage: 0x7FF800000000, SizeOfImage: 0x100000, Name: "lsasrv.dll"},
	}
	blob := buildFixture(t, mods, nil)
	res, _ := Parse(bytes.NewReader(blob), int64(len(blob)))
	// Parse returns ErrUnsupportedBuild without templates, but still
	// fills in Modules — that's exactly the path module tests cover.
	if res == nil {
		t.Fatal("Parse: res == nil (want partial Result with Modules populated)")
	}
	if _, ok := res.ModuleByName("nonexistent.dll"); ok {
		t.Error("ModuleByName(nonexistent.dll) returned ok=true, want false")
	}
}

// TestParse_PopulatesModulesField confirms the public Modules slice
// surfaces every entry from the dump in declaration order. Critical
// for phase 3 where the pattern scanner walks Modules to locate the
// LSA crypto globals.
func TestParse_PopulatesModulesField(t *testing.T) {
	mods := []lsassdump.Module{
		{BaseOfImage: 0x7FF800000000, SizeOfImage: 0x100000, Name: "lsasrv.dll", TimeDateStamp: 0x60000001, CheckSum: 0xABCD},
		{BaseOfImage: 0x7FF801000000, SizeOfImage: 0x080000, Name: "msv1_0.dll"},
		{BaseOfImage: 0x7FF802000000, SizeOfImage: 0x0A0000, Name: "kerberos.dll"},
	}
	blob := buildFixture(t, mods, nil)
	res, _ := Parse(bytes.NewReader(blob), int64(len(blob)))
	// Parse returns ErrUnsupportedBuild without templates, but still
	// fills in Modules — that's exactly the path module tests cover.
	if res == nil {
		t.Fatal("Parse: res == nil (want partial Result with Modules populated)")
	}
	if len(res.Modules) != 3 {
		t.Fatalf("len(Modules) = %d, want 3", len(res.Modules))
	}
	for i, want := range []string{"lsasrv.dll", "msv1_0.dll", "kerberos.dll"} {
		if res.Modules[i].Name != want {
			t.Errorf("Modules[%d].Name = %q, want %q", i, res.Modules[i].Name, want)
		}
	}
	if res.Modules[0].TimeDateStamp != 0x60000001 {
		t.Errorf("Modules[0].TimeDateStamp = 0x%X, want 0x60000001", res.Modules[0].TimeDateStamp)
	}
	if res.Modules[0].CheckSum != 0xABCD {
		t.Errorf("Modules[0].CheckSum = 0x%X, want 0xABCD", res.Modules[0].CheckSum)
	}
}
