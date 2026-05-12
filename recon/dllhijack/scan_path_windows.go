//go:build windows

package dllhijack

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// ScanPATHWritable enumerates every directory in the system + user
// `%PATH%` and emits one Opportunity per writable entry. Mirrors the
// pattern itm4n documented for the MareBackup PrivEsc (a SYSTEM-context
// scheduled task whose call chain ends in
// `CreateProcessW(L"powershell.exe", …)` — unqualified, so the EXE
// search order kicks in and reaches `%PATH%`).
//
// The reported [Opportunity] has:
//
//   - Kind          = [KindPathHijack]
//   - SearchDir     = the writable PATH entry (drop dir)
//   - Writable      = true (the scanner already probed)
//   - IntegrityGain = true iff the dir came from the system hive
//     (HKLM\…\Session Manager\Environment\Path). User-hive dirs only
//     fire for processes the same user launches → no elevation.
//   - BinaryPath / HijackedDLL / HijackedPath = "" (the victim is
//     not a single binary — every higher-integrity process making an
//     unqualified CreateProcess is a potential consumer).
//
// Unlike [ScanServices] / [ScanProcesses] / [ScanScheduledTasks], no
// PE imports are walked: the unqualified-exec pattern these
// Opportunities exploit lives in runtime `CreateProcessW` string
// literals and is invisible to static IAT analysis. Operators pair
// this scan with manual ProcMon to find the actual consumer; the
// scan answers "is the precondition (writable system-PATH dir)
// reachable from my token?".
//
// Requires no elevation. opts is accepted for API symmetry with the
// rest of the scanner family — [ScanOpts.Opener] is unused here (no
// PE reads).
func ScanPATHWritable(opts ...ScanOpts) ([]Opportunity, error) {
	_ = firstOpts(opts) // signature symmetry; no PE reads in this scan.

	sysPath, err := readEnvPath(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`)
	if err != nil {
		return nil, fmt.Errorf("dllhijack/path: read system PATH: %w", err)
	}
	usrPath, _ := readEnvPath(registry.CURRENT_USER, `Environment`)
	// User PATH absent is normal — many accounts never set one.

	entries := mergePathSources(sysPath, usrPath)
	var opps []Opportunity
	for _, e := range entries {
		dir := expandEnvVars(e.Dir)
		if !dirWritable(dir) {
			continue
		}
		hive := "user"
		if e.FromSystem {
			hive = "system"
		}
		opp := Opportunity{
			Kind:        KindPathHijack,
			ID:          dir,
			DisplayName: hive + " PATH entry",
			SearchDir:   dir,
			Writable:    true,
			Reason: "writable " + hive + " %PATH% dir — any unqualified " +
				"CreateProcess from a higher-integrity context (services, " +
				"scheduled tasks; cf. MareBackup chain) walks here before " +
				"reaching System32",
			IntegrityGain: e.FromSystem,
		}
		opps = append(opps, opp)
	}
	return opps, nil
}

// readEnvPath fetches the `Path` value under root\subkey. Missing key
// or missing value both return ("", nil) so an absent user PATH does
// not abort the system-PATH scan.
func readEnvPath(root registry.Key, subkey string) (string, error) {
	k, err := registry.OpenKey(root, subkey, registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return "", nil
		}
		return "", err
	}
	defer k.Close()
	val, _, err := k.GetStringValue("Path")
	if err != nil {
		if err == registry.ErrNotExist {
			return "", nil
		}
		return "", err
	}
	return val, nil
}
