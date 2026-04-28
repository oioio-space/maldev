//go:build windows

package version_test

import (
	"fmt"

	"github.com/oioio-space/maldev/win/version"
)

// Current reads RtlGetVersion (kernel-side, manifest-shim free) plus
// the registry UBR — the value applications use to gate
// build-specific syscall SSN tables.
func ExampleCurrent() {
	v := version.Current()
	fmt.Printf("%s build %d\n", v, v.BuildNumber)
}

// AtLeast gates technique selection on a minimum build — pair with
// the WINDOWS_10_* and WINDOWS_11_* constants exported by this
// package.
func ExampleAtLeast() {
	if version.AtLeast(version.WINDOWS_10_1809) {
		// callback-array tampering primitives are stable from 1809+
	}
}

// CVE202430088 reports patched / unpatched state of the kernel
// TOCTOU primitive consumed by privesc/cve202430088. Pre-flight
// check for the exploit chain.
func ExampleCVE202430088() {
	info, err := version.CVE202430088()
	if err != nil {
		fmt.Println("cve:", err)
		return
	}
	if info.Vulnerable {
		fmt.Printf("vuln: %s build %d.%d\n", info.Edition, info.Build, info.Revision)
	}
}
