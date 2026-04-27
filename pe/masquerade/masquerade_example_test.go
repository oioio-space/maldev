package masquerade_test

import (
	"github.com/oioio-space/maldev/pe/masquerade"
)

// Clone is the one-shot path: pull manifest + icons + VERSIONINFO
// from a source PE and emit a linkable .syso the Go toolchain
// picks up at compile time.
func ExampleClone() {
	if err := masquerade.Clone(
		`C:\Windows\System32\svchost.exe`,
		"resource.syso",
		masquerade.AMD64,
		masquerade.AsInvoker,
	); err != nil {
		return
	}
}

// Build composes the Option chain — useful when callers want to
// override individual fields (custom OriginalFilename, swap the
// icon for a PNG, or re-attach a stolen certificate from
// pe/cert).
func ExampleBuild() {
	if err := masquerade.Build("resource.syso", masquerade.AMD64,
		masquerade.WithSourcePE(`C:\Windows\System32\svchost.exe`),
		masquerade.WithExecLevel(masquerade.RequireAdministrator),
		masquerade.WithVersionInfo(&masquerade.VersionInfo{
			OriginalFilename: "myservice.exe",
			CompanyName:      "Microsoft Corporation",
			FileVersion:      "10.0.19041.1",
		}),
	); err != nil {
		return
	}
}
