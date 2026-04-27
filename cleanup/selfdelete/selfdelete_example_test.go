//go:build windows && selfdelete_demo

// Build-tag-gated: invoking ExampleRun at test time really tries to
// delete the test binary while it's running. To exercise:
//
//	go test -tags 'selfdelete_demo' ./cleanup/selfdelete/...
package selfdelete_test

import (
	"fmt"
	"time"

	"github.com/oioio-space/maldev/cleanup/selfdelete"
)

// Run renames the running EXE's default :$DATA stream and marks it for
// deletion. Process keeps executing from its mapped image.
func ExampleRun() {
	if err := selfdelete.Run(); err != nil {
		fmt.Println("self-delete failed:", err)
	}
	// process continues…
}

// MarkForDeletion schedules deletion at the next reboot via
// MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT). Useful when the ADS path is
// blocked.
func ExampleMarkForDeletion() {
	_ = selfdelete.MarkForDeletion()
}

// RunWithScript is the FAT-volume / locked-down fallback. Drops a
// .bat next to the EXE that polls until the process exits, then
// deletes. More signature-noisy than Run.
func ExampleRunWithScript() {
	_ = selfdelete.RunWithScript(2 * time.Second)
}
