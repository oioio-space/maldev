//go:build !windows

package shell

import "github.com/oioio-space/maldev/evasion"

func applyEvasion(_ []evasion.Technique, _ evasion.Caller) error { return nil }
