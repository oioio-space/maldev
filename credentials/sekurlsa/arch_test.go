package sekurlsa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/credentials/lsassdump"
)

// TestParse_RejectsX86Dump verifies the architecture gate fires when
// SystemInfo.ProcessorArchitecture is 0 (x86) — the parser surfaces
// ErrUnsupportedArchitecture and the partial Result still carries
// BuildNumber + Architecture so the caller can report the rejection.
func TestParse_RejectsX86Dump(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()

	cfg := lsassdump.Config{
		TimeDateStamp: 0x60000000,
		SystemInfo: lsassdump.SystemInfo{
			ProcessorArchitecture: 0, // x86
			NumberOfProcessors:    1,
			BuildNumber:           7601, // Win 7 SP1 — typical 32-bit era
			MajorVersion:          6,
			MinorVersion:          1,
			PlatformID:            2,
		},
	}
	var buf bytes.Buffer
	if _, err := lsassdump.Build(&buf, cfg); err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	blob := buf.Bytes()

	res, err := Parse(bytes.NewReader(blob), int64(len(blob)))
	if !errors.Is(err, ErrUnsupportedArchitecture) {
		t.Fatalf("err = %v, want ErrUnsupportedArchitecture", err)
	}
	if res == nil {
		t.Fatal("res = nil; want partial Result with arch+build")
	}
	if res.Architecture != ArchX86 {
		t.Errorf("Architecture = %v, want ArchX86", res.Architecture)
	}
	if res.BuildNumber != 7601 {
		t.Errorf("BuildNumber = %d, want 7601", res.BuildNumber)
	}
}

// TestParse_RejectsUnknownArch covers the catch-all path for any
// processor architecture that isn't AMD64 (9) or x86 (0) — ARM64,
// IA-64, etc. — they all fall under ArchUnknown and should produce
// the same sentinel.
func TestParse_RejectsUnknownArch(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()

	cfg := lsassdump.Config{
		TimeDateStamp: 0x60000000,
		SystemInfo: lsassdump.SystemInfo{
			ProcessorArchitecture: 12, // ARM64 — not yet supported
			BuildNumber:           22621,
		},
	}
	var buf bytes.Buffer
	if _, err := lsassdump.Build(&buf, cfg); err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	blob := buf.Bytes()

	res, err := Parse(bytes.NewReader(blob), int64(len(blob)))
	if !errors.Is(err, ErrUnsupportedArchitecture) {
		t.Fatalf("err = %v, want ErrUnsupportedArchitecture", err)
	}
	if res.Architecture != ArchUnknown {
		t.Errorf("Architecture = %v, want ArchUnknown", res.Architecture)
	}
}
