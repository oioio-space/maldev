package packer_test

import (
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestFormatString covers every Format constant's String()
// rendering. Includes the v0.109.0 FormatWindowsDLL stub —
// the constant is wired through but the actual DLL stub is
// not yet implemented (selecting it triggers transform.ErrIsDLL
// until the stub work in packer-dll-format-plan.md ships).
func TestFormatString(t *testing.T) {
	cases := []struct {
		f    packer.Format
		want string
	}{
		{packer.FormatWindowsExe, "windows-exe"},
		{packer.FormatLinuxELF, "linux-elf"},
		{packer.FormatWindowsDLL, "windows-dll"},
		{packer.FormatUnknown, "format(0)"},
	}
	for _, c := range cases {
		if got := c.f.String(); got != c.want {
			t.Errorf("Format(%d).String() = %q, want %q", c.f, got, c.want)
		}
	}
}
