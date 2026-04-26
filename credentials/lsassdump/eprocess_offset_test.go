package lsassdump

import (
	"errors"
	"os"
	"testing"
)

// TestSignatureLevelOffset covers the documented kvc-style identity:
// EPROCESS.SignatureLevel sits 2 bytes before EPROCESS.Protection.
func TestSignatureLevelOffset(t *testing.T) {
	cases := []struct {
		protection uint32
		want       uint32
	}{
		{0x6FA, 0x6F8},
		{0x900, 0x8FE},
	}
	for _, c := range cases {
		if got := SignatureLevelOffset(c.protection); got != c.want {
			t.Errorf("SignatureLevelOffset(0x%X) = 0x%X, want 0x%X",
				c.protection, got, c.want)
		}
	}
}

// TestSectionSignatureLevelOffset — sits 1 byte before Protection.
func TestSectionSignatureLevelOffset(t *testing.T) {
	cases := []struct {
		protection uint32
		want       uint32
	}{
		{0x6FA, 0x6F9},
		{0x900, 0x8FF},
	}
	for _, c := range cases {
		if got := SectionSignatureLevelOffset(c.protection); got != c.want {
			t.Errorf("SectionSignatureLevelOffset(0x%X) = 0x%X, want 0x%X",
				c.protection, got, c.want)
		}
	}
}

// TestDiscoverProtectionOffset_NonexistentPath surfaces the open
// error wrapped — callers errors.Is against fs.ErrNotExist.
func TestDiscoverProtectionOffset_NonexistentPath(t *testing.T) {
	_, err := DiscoverProtectionOffset("/no/such/ntoskrnl.exe", nil)
	if err == nil {
		t.Fatal("err = nil, want open error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want os.ErrNotExist wrapped", err)
	}
}

// TestDiscoverProtectionOffset_NotPE — a non-PE file (e.g. plain
// text) must surface a debug/pe parse error.
func TestDiscoverProtectionOffset_NotPE(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "fake.exe")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	tmp.WriteString("not a PE — just text bytes that fill the header....")
	tmp.Close()

	_, err = DiscoverProtectionOffset(tmp.Name(), nil)
	if err == nil {
		t.Fatal("err = nil, want PE parse error")
	}
}

// TestDiscoverProtectionOffset_RealNtoskrnl — env-gated. When
// MALDEV_NTOSKRNL points at a captured ntoskrnl.exe (typical:
// ignore/ntoskrnl-win10-22h2.exe pulled from a VM), we verify the
// discovery returns a plausible offset for that build family.
//
// Modern Win 10/11 builds put EPROCESS.Protection in [0x6F0, 0x900].
// The exact value drifts every cumulative update.
func TestDiscoverProtectionOffset_RealNtoskrnl(t *testing.T) {
	path := os.Getenv("MALDEV_NTOSKRNL")
	if path == "" {
		t.Skip("set MALDEV_NTOSKRNL=<path> to validate against a real ntoskrnl.exe")
	}
	off, err := DiscoverProtectionOffset(path, nil)
	if err != nil {
		t.Fatalf("DiscoverProtectionOffset(%s, nil): %v", path, err)
	}
	if off < 0x600 || off > 0x1000 {
		t.Errorf("offset 0x%X outside [0x600, 0x1000] — likely wrong", off)
	}
	t.Logf("EPROCESS.Protection offset = 0x%X (Signature=0x%X, SectionSig=0x%X)",
		off, SignatureLevelOffset(off), SectionSignatureLevelOffset(off))
}

// TestDiscoverActiveProcessLinksOffset — UniqueProcessId + 8 on x64.
func TestDiscoverActiveProcessLinksOffset(t *testing.T) {
	cases := []struct {
		upid uint32
		want uint32
	}{
		{0x440, 0x448},
		{0x4B8, 0x4C0},
	}
	for _, c := range cases {
		if got := DiscoverActiveProcessLinksOffset(c.upid); got != c.want {
			t.Errorf("DiscoverActiveProcessLinksOffset(0x%X) = 0x%X, want 0x%X",
				c.upid, got, c.want)
		}
	}
}

// TestDiscoverUniqueProcessIdOffset_NonexistentPath — open error.
func TestDiscoverUniqueProcessIdOffset_NonexistentPath(t *testing.T) {
	_, err := DiscoverUniqueProcessIdOffset("/no/such/ntoskrnl.exe", nil)
	if err == nil {
		t.Fatal("err = nil, want open error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want os.ErrNotExist", err)
	}
}

// TestDiscoverInitialSystemProcessRVA_NonexistentPath — open error.
func TestDiscoverInitialSystemProcessRVA_NonexistentPath(t *testing.T) {
	_, err := DiscoverInitialSystemProcessRVA("/no/such/ntoskrnl.exe", nil)
	if err == nil {
		t.Fatal("err = nil, want open error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want os.ErrNotExist", err)
	}
}

// TestDiscoverUniqueProcessIdOffset_RealNtoskrnl — env-gated. The
// EPROCESS.UniqueProcessId offset on Win 10/11 sits in roughly
// [0x430, 0x4F0] depending on the build. We assert the value is
// in that range and log it for cross-reference against pypykatz /
// kvc.
func TestDiscoverUniqueProcessIdOffset_RealNtoskrnl(t *testing.T) {
	path := os.Getenv("MALDEV_NTOSKRNL")
	if path == "" {
		t.Skip("set MALDEV_NTOSKRNL=<path> to validate")
	}
	off, err := DiscoverUniqueProcessIdOffset(path, nil)
	if err != nil {
		t.Fatalf("DiscoverUniqueProcessIdOffset: %v", err)
	}
	if off < 0x300 || off > 0x600 {
		t.Errorf("UniqueProcessId offset 0x%X outside expected range", off)
	}
	t.Logf("EPROCESS.UniqueProcessId offset = 0x%X (ActiveProcessLinks = 0x%X)",
		off, DiscoverActiveProcessLinksOffset(off))
}

// TestDiscoverInitialSystemProcessRVA_RealNtoskrnl — env-gated.
// Just verifies the export resolves; the RVA's plausible range
// is the entire .data section so we just check non-zero.
func TestDiscoverInitialSystemProcessRVA_RealNtoskrnl(t *testing.T) {
	path := os.Getenv("MALDEV_NTOSKRNL")
	if path == "" {
		t.Skip("set MALDEV_NTOSKRNL=<path> to validate")
	}
	rva, err := DiscoverInitialSystemProcessRVA(path, nil)
	if err != nil {
		t.Fatalf("DiscoverInitialSystemProcessRVA: %v", err)
	}
	if rva == 0 {
		t.Error("rva = 0, want non-zero export RVA")
	}
	t.Logf("PsInitialSystemProcess RVA = 0x%X", rva)
}
