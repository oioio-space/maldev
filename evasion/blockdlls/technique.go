//go:build windows

package blockdlls

import (
	"github.com/oioio-space/maldev/evasion"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

type microsoftOnlyTechnique struct{}

func (microsoftOnlyTechnique) Name() string { return "blockdlls:MicrosoftOnly" }
func (microsoftOnlyTechnique) Apply(c evasion.Caller) error {
	var wc *wsyscall.Caller
	if c != nil {
		if typed, ok := c.(*wsyscall.Caller); ok {
			wc = typed
		}
	}
	return Enable(wc)
}

// MicrosoftOnly returns a Technique that blocks non-Microsoft-signed DLLs.
//
// How it works: calls SetProcessMitigationPolicy to set MicrosoftSignedOnly=1
// on the binary signature policy. After this, only DLLs signed by Microsoft
// can be loaded into the process. This prevents EDR agent DLLs (which are
// signed by the EDR vendor, not Microsoft) from being injected.
//
// WARNING: This is IRREVERSIBLE. Some legitimate DLLs may also be blocked.
func MicrosoftOnly() evasion.Technique { return microsoftOnlyTechnique{} }
