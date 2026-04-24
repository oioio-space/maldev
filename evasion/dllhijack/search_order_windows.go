//go:build windows

package dllhijack

import (
	"os"
	"path/filepath"
	"strings"

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
//   - Otherwise, walk the search order until the DLL is found
//     (resolved). Report the FIRST dir earlier than resolved that is
//     user-writable AND does not already contain dllName.
//
// Returns (hijackDir, resolvedDir):
//   - hijackDir: directory where an attacker-dropped DLL would win, or "".
//   - resolvedDir: where the DLL currently resolves to, or "" if not
//     present anywhere on the search order.
func HijackPath(exeDir, dllName string) (hijackDir, resolvedDir string) {
	if isKnownDLL(dllName) {
		return "", ""
	}
	dirs := SearchOrder(exeDir)

	resolvedIdx := -1
	for i, dir := range dirs {
		if fileExists(filepath.Join(dir, dllName)) {
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
		if fileExists(filepath.Join(dir, dllName)) {
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

// isKnownDLL returns true when dllName is listed in
// HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs,
// meaning Windows bypasses the search order for it.
func isKnownDLL(dllName string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`,
		registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return false
	}
	// Keys here are strings like "version" with the value being "version.dll".
	// Match case-insensitively on both the value name and its data.
	want := strings.ToLower(strings.TrimSuffix(dllName, ".dll"))
	for _, n := range names {
		if strings.EqualFold(n, want) {
			return true
		}
		val, _, err := k.GetStringValue(n)
		if err == nil && strings.EqualFold(val, dllName) {
			return true
		}
	}
	return false
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
