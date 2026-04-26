//go:build windows

package sekurlsa

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// terminatePID kills the process at pid and ignores errors. Used by
// the partial-implementation tests that exercise the spawn path —
// each must clean up its own suspended decoy so test runs don't
// accumulate orphaned processes on the Win VM.
func terminatePID(pid uint32) {
	if pid == 0 {
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return
	}
	_ = windows.TerminateProcess(h, 1)
	_ = windows.CloseHandle(h)
}

// validPTHParams is the minimal happy-path Params used as a base for
// the rejection tests below — each test mutates exactly one field
// to the bad shape it asserts against.
func validPTHParams() PTHParams {
	return PTHParams{
		Target: PTHTarget{
			Domain:   "corp.example.com",
			Username: "Administrator",
			NTLM:     bytes.Repeat([]byte{0xAA}, 16),
		},
	}
}

func TestPass_RejectsMissingDomain(t *testing.T) {
	p := validPTHParams()
	p.Target.Domain = ""
	_, err := Pass(p)
	if !errors.Is(err, ErrPTHInvalidTarget) {
		t.Fatalf("Pass: err = %v, want wrap of ErrPTHInvalidTarget", err)
	}
}

func TestPass_RejectsMissingUsername(t *testing.T) {
	p := validPTHParams()
	p.Target.Username = ""
	_, err := Pass(p)
	if !errors.Is(err, ErrPTHInvalidTarget) {
		t.Fatalf("Pass: err = %v, want wrap of ErrPTHInvalidTarget", err)
	}
}

func TestPass_RejectsBadNTLMLength(t *testing.T) {
	cases := [][]byte{
		nil,
		bytes.Repeat([]byte{1}, 8),  // too short
		bytes.Repeat([]byte{1}, 32), // too long
	}
	for _, ntlm := range cases {
		p := validPTHParams()
		p.Target.NTLM = ntlm
		_, err := Pass(p)
		if !errors.Is(err, ErrPTHInvalidTarget) {
			t.Errorf("NTLM len=%d: err = %v, want wrap of ErrPTHInvalidTarget", len(ntlm), err)
		}
	}
}

func TestPass_RejectsBadAES128Length(t *testing.T) {
	p := validPTHParams()
	p.Target.AES128 = bytes.Repeat([]byte{1}, 17) // not empty, not 16
	_, err := Pass(p)
	if !errors.Is(err, ErrPTHInvalidTarget) {
		t.Fatalf("Pass: err = %v, want wrap of ErrPTHInvalidTarget", err)
	}
}

func TestPass_RejectsBadAES256Length(t *testing.T) {
	p := validPTHParams()
	p.Target.AES256 = bytes.Repeat([]byte{1}, 31) // not empty, not 32
	_, err := Pass(p)
	if !errors.Is(err, ErrPTHInvalidTarget) {
		t.Fatalf("Pass: err = %v, want wrap of ErrPTHInvalidTarget", err)
	}
}

// TestPass_StubReturnsNotImplementedAfterSpawn documents the
// chantier-II partial-implementation contract: with valid Params,
// Pass spawns a CREATE_SUSPENDED decoy under
// LOGON_NETCREDENTIALS_ONLY, captures the spawned PID + LUID into
// the returned PTHResult, and surfaces ErrPTHNotImplemented to
// signal the LSA write-back step is still pending. The test
// terminates the spawned process so it doesn't accumulate.
func TestPass_StubReturnsNotImplementedAfterSpawn(t *testing.T) {
	res, err := Pass(validPTHParams())
	defer terminatePID(res.PID)

	if !errors.Is(err, ErrPTHNotImplemented) {
		t.Fatalf("Pass with valid params: err = %v, want wrap of ErrPTHNotImplemented", err)
	}
	if res.PID == 0 {
		t.Errorf("Pass spawn: PID = 0, want non-zero")
	}
	if res.LogonID == 0 {
		t.Errorf("Pass spawn: LogonID = 0, want non-zero LUID")
	}
}

func TestPassImpersonate_RejectsMissingDomain(t *testing.T) {
	p := validPTHParams()
	p.Target.Domain = ""
	_, err := PassImpersonate(p)
	if !errors.Is(err, ErrPTHInvalidTarget) {
		t.Fatalf("PassImpersonate: err = %v, want wrap of ErrPTHInvalidTarget", err)
	}
}

func TestPassImpersonate_StubReturnsNotImplementedAfterSpawn(t *testing.T) {
	res, err := PassImpersonate(validPTHParams())
	defer terminatePID(res.PID)

	if !errors.Is(err, ErrPTHNotImplemented) {
		t.Fatalf("PassImpersonate: err = %v, want wrap of ErrPTHNotImplemented", err)
	}
	if res.PID == 0 {
		t.Errorf("PassImpersonate spawn: PID = 0, want non-zero")
	}
	if res.LogonID == 0 {
		t.Errorf("PassImpersonate spawn: LogonID = 0, want non-zero LUID")
	}
}

// Cross-platform TestMutateMSVPrimary_* + TestPTHSentinels_AreDistinct
// live in pth_msv_test.go (no build tag) since the symbols they cover
// are defined in pth.go and pth_msv.go.
