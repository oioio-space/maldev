//go:build windows

// kernel-byovd — panorama 16 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/kernel/byovd-rtcore64.md  — Driver{Install/ReadKernel/Uninstall}
//
// Tests the BYOVD lifecycle. The default build tag set ships WITHOUT the
// signed RTCore64.sys bytes, so Install should return ErrDriverBytesMissing
// before any SCM call — meaning admin and lowuser get the same error and
// the matrix probes only the tag-gated default path.
//
// To exercise the real lifecycle, build with `-tags=byovd_rtcore64` after
// dropping a sibling file containing `//go:embed RTCore64.sys` per the
// doc's Driver binary section.
package main

import (
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/kernel/driver"
	"github.com/oioio-space/maldev/kernel/driver/rtcore64"
)

func main() {
	var d rtcore64.Driver

	// 1. Install — the doc-claimed entry point.
	fmt.Println("=== rtcore64.Driver.Install ===")
	err := d.Install()
	switch {
	case err == nil:
		fmt.Printf("Install: OK (driver loaded — call Uninstall before exit)\n")
		_ = d.Uninstall()
	case errors.Is(err, driver.ErrPrivilegeRequired):
		fmt.Printf("Install: ErrPrivilegeRequired (need admin)\n")
	default:
		// Likely ErrDriverBytesMissing on a default-tag build.
		fmt.Printf("Install: %v\n", err)
	}
}
