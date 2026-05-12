//go:build windows

package dllhijack

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// SearchOrder returns the directories Windows walks to resolve a DLL
// load from an exe living in exeDir. Order: app dir → System32 →
// SysWOW64 → Windows dir. (SafeDllSearchMode is assumed enabled — the
// default since Windows XP SP1 — so CWD is NOT included; we also skip
// %PATH% since it's environment-dependent and non-deterministic for
// service contexts.)
//
// For a strict, KnownDLLs-aware resolution, use HijackPath.
func SearchOrder(exeDir string) []string {
	sys32 := systemDirectory()
	win := windowsDirectory()
	dirs := []string{exeDir, sys32}
	// SysWOW64 only applies to WoW64 processes loading 32-bit DLLs. Include
	// it for completeness; callers can filter if irrelevant.
	if sw := filepath.Join(win, "SysWOW64"); sw != sys32 {
		dirs = append(dirs, sw)
	}
	dirs = append(dirs, win)
	return dirs
}

// HijackPath computes the classical DLL-search-order hijack candidate
// for a single (exe, importedDLL) pair:
//
//   - If dllName is a KnownDLL (registry list), the loader goes straight
//     to System32 regardless of search order — no hijack possible;
//     returns zero-values.
//   - If dllName matches an ApiSet contract (api-ms-win-* / ext-ms-win-*),
//     the loader redirects via the in-PEB ApiSet schema and never reads
//     from disk — also unhijackable; returns zero-values.
//   - Otherwise, walk the search order until the DLL is found
//     (resolved). Report the FIRST dir earlier than resolved that is
//     user-writable AND does not already contain dllName.
//
// Returns (hijackDir, resolvedDir):
//   - hijackDir: directory where an attacker-dropped DLL would win, or "".
//   - resolvedDir: where the DLL currently resolves to, or "" if not
//     present anywhere on the search order.
func HijackPath(exeDir, dllName string) (hijackDir, resolvedDir string) {
	if isKnownDLL(dllName) || isApiSet(dllName) {
		return "", ""
	}
	dirs := SearchOrder(exeDir)

	// Cache os.Stat results so the two loops don't stat the same path
	// twice. Materially reduces syscalls on a full-system scan (each
	// HijackPath call goes from up to 8 stats down to 4, and the
	// outer scanner loops keep calling HijackPath for the same app
	// dirs).
	stats := make(map[string]bool, len(dirs))
	exists := func(path string) bool {
		if v, ok := stats[path]; ok {
			return v
		}
		v := fileExists(path)
		stats[path] = v
		return v
	}

	resolvedIdx := -1
	for i, dir := range dirs {
		if exists(filepath.Join(dir, dllName)) {
			resolvedIdx = i
			resolvedDir = dir
			break
		}
	}
	if resolvedIdx <= 0 {
		// Either not found anywhere, or resolves at the first search-order
		// entry (app dir itself) — no opportunity strictly earlier.
		return "", resolvedDir
	}

	for i := 0; i < resolvedIdx; i++ {
		dir := dirs[i]
		if exists(filepath.Join(dir, dllName)) {
			// Earlier dir already has a copy — loader would resolve
			// there, not the supposed resolvedIdx. Skip.
			continue
		}
		if dirWritable(dir) {
			return dir, resolvedDir
		}
	}
	return "", resolvedDir
}

// knownDLLs is the cached KnownDLLs set, loaded once per process via
// sync.Once. Reading the registry on every isKnownDLL call dominated
// scanner cost on servers with many services — this turns an O(N×M)
// registry workload into O(1) lookups after the first call.
var (
	knownDLLsOnce sync.Once
	knownDLLs     map[string]struct{}
)

func loadKnownDLLs() {
	knownDLLs = make(map[string]struct{})
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`,
		registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return
	}
	for _, n := range names {
		// Value name (e.g. "version") AND value data (e.g. "version.dll") —
		// both are hijack-protected; store both forms lowercased.
		knownDLLs[strings.ToLower(n)+".dll"] = struct{}{}
		if val, _, err := k.GetStringValue(n); err == nil {
			knownDLLs[strings.ToLower(val)] = struct{}{}
		}
	}
}

// isKnownDLL returns true when dllName is listed in
// HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs,
// meaning Windows bypasses the search order for it. Lookup is O(1)
// after first call (sync.Once-guarded).
func isKnownDLL(dllName string) bool {
	knownDLLsOnce.Do(loadKnownDLLs)
	_, ok := knownDLLs[strings.ToLower(dllName)]
	return ok
}

func systemDirectory() string {
	s, _ := windows.GetSystemDirectory()
	return s
}

func windowsDirectory() string {
	s, _ := windows.GetWindowsDirectory()
	return s
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
