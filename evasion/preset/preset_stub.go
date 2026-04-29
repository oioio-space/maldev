//go:build !windows

package preset

import "github.com/oioio-space/maldev/evasion"

type cetDisableStub struct{}

func (cetDisableStub) Name() string                  { return "cet.Disable" }
func (cetDisableStub) Apply(_ evasion.Caller) error  { return nil }

func CETOptOut() evasion.Technique  { return cetDisableStub{} }

func Minimal() []evasion.Technique    { return nil }
func Stealth() []evasion.Technique    { return nil }
func Hardened() []evasion.Technique   { return nil }
func Aggressive() []evasion.Technique { return nil }
