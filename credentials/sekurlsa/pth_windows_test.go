//go:build windows

package sekurlsa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/testutil"
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

// TestPass_LiveMSVWriteBack exercises the full MSV write-back path
// against the live lsass on the test VM. Intrusive: opens lsass
// with PROCESS_VM_READ + PROCESS_VM_WRITE and overwrites the
// PrimaryCredentials cipher of the spawned process's logon
// session. The test admin's own session is never touched (the
// spawn creates a fresh LUID via LOGON_NETCREDENTIALS_ONLY). The
// spawned process is terminated post-test.
func TestPass_LiveMSVWriteBack(t *testing.T) {
	testutil.RequireIntrusive(t)

	res, err := Pass(validPTHParams())
	defer terminatePID(res.PID)

	if err != nil {
		t.Fatalf("Pass: %v (PID=%d LUID=0x%X)", err, res.PID, res.LogonID)
	}
	if res.PID == 0 {
		t.Errorf("PID = 0, want non-zero")
	}
	if res.LogonID == 0 {
		t.Errorf("LogonID = 0, want non-zero LUID")
	}
	if !res.MSVOverwritten {
		t.Errorf("MSVOverwritten = false, want true after successful write-back")
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

// TestPassImpersonate_LiveMSVWriteBack — same as
// TestPass_LiveMSVWriteBack since PassImpersonate currently
// delegates to Pass (the SetThreadToken impersonation flow is the
// final chantier-II slice).
func TestPassImpersonate_LiveMSVWriteBack(t *testing.T) {
	testutil.RequireIntrusive(t)

	res, err := PassImpersonate(validPTHParams())
	defer terminatePID(res.PID)

	if err != nil {
		t.Fatalf("PassImpersonate: %v (PID=%d LUID=0x%X)", err, res.PID, res.LogonID)
	}
	if !res.MSVOverwritten {
		t.Errorf("MSVOverwritten = false, want true")
	}
}

// Cross-platform TestMutateMSVPrimary_* + TestPTHSentinels_AreDistinct
// live in pth_msv_test.go (no build tag) since the symbols they cover
// are defined in pth.go and pth_msv.go.
