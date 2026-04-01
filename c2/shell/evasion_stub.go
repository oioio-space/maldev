//go:build !windows

package shell

// applyEvasion is a no-op on non-Windows platforms.
func applyEvasion(cfg *EvasionConfig) error { return nil }
