//go:build windows

package fakecmd_test

import (
	"github.com/oioio-space/maldev/process/tamper/fakecmd"
)

// Spoof overwrites the current process's PEB CommandLine so
// process listings show a fake line. Restore writes the
// original back — defer it so long-running processes don't
// ship the fake line into telemetry.
func ExampleSpoof() {
	if err := fakecmd.Spoof(
		`C:\Windows\System32\svchost.exe -k netsvcs`,
		nil,
	); err != nil {
		return
	}
	defer fakecmd.Restore()

	// Subsequent Process Explorer / wmic / Get-Process queries
	// see the spoofed command line.
}
