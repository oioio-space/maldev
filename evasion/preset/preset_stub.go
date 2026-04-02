//go:build !windows

package preset

import "github.com/oioio-space/maldev/evasion"

func Minimal() []evasion.Technique    { return nil }
func Stealth() []evasion.Technique    { return nil }
func Aggressive() []evasion.Technique { return nil }
