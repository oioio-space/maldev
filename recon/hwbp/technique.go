//go:build windows

package hwbp

import "github.com/oioio-space/maldev/evasion"

type detectAllTechnique struct{}

func (detectAllTechnique) Name() string { return "hwbp:DetectAll" }
func (detectAllTechnique) Apply(_ evasion.Caller) error {
	// DetectAll + ClearAll: detect hooks then clear breakpoints.
	// hwbp uses WinAPI directly (no syscall caller support).
	if _, err := DetectAll(); err != nil {
		return err
	}
	_, err := ClearAll()
	return err
}

// Technique returns an evasion.Technique that detects and clears
// all hardware breakpoints on every thread in the current process.
func Technique() evasion.Technique { return detectAllTechnique{} }
