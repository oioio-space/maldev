//go:build windows

// recon-suite — panorama 3 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/recon/anti-analysis.md (antidebug + antivm)
//   - docs/techniques/recon/sandbox.md
//   - docs/techniques/recon/timing.md
//   - docs/techniques/recon/drive.md
//   - docs/techniques/recon/folder.md
//   - docs/techniques/recon/network.md
//   - docs/techniques/recon/hw-breakpoints.md
//
// The "before-detonation environment audit" panorama: every check a
// real implant runs at startup before deciding to continue. Tests
// what surfaces at admin vs lowuser — most should be identical
// (these are observation primitives, not privileged operations).
package main

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/recon/antidebug"
	"github.com/oioio-space/maldev/recon/antivm"
	"github.com/oioio-space/maldev/recon/drive"
	"github.com/oioio-space/maldev/recon/folder"
	"github.com/oioio-space/maldev/recon/hwbp"
	"github.com/oioio-space/maldev/recon/network"
	"github.com/oioio-space/maldev/recon/sandbox"
)

func main() {
	// 1. Anti-debug + anti-VM (anti-analysis.md "Simple").
	fmt.Printf("=== Anti-analysis ===\n")
	fmt.Printf("debugger present: %v\n", antidebug.IsDebuggerPresent())
	if name, _ := antivm.Detect(antivm.DefaultConfig()); name != "" {
		fmt.Printf("VM detected: %s\n", name)
	} else {
		fmt.Printf("VM detected: none\n")
	}

	// 2. Sandbox composite check (sandbox.md "Simple").
	fmt.Printf("\n=== Sandbox ===\n")
	sc := sandbox.New(sandbox.DefaultConfig())
	if hit, reason, _ := sc.IsSandboxed(context.Background()); hit {
		fmt.Printf("sandboxed: %s\n", reason)
	} else {
		fmt.Printf("sandboxed: no\n")
	}

	// 3. Timing burn (timing.md "Simple", shortened from 30s to 200ms so
	//    the matrix run finishes promptly — the doc's 30s is for real
	//    payloads).
	fmt.Printf("\n=== Timing burn ===\n")
	t0 := time.Now()
	// timing.BusyWait — but we keep this short for the audit.
	for time.Since(t0) < 200*time.Millisecond {
	}
	fmt.Printf("burn elapsed: %v\n", time.Since(t0).Round(time.Millisecond))

	// 4. Drive lookup (drive.md "Simple").
	fmt.Printf("\n=== Drive ===\n")
	// DOC-DRIFT (drive.md "Simple"): doc shows drive.New("C:") but the
	// real API rejects that with "syntax incorrect" on Win10 + Win11. The
	// caller must pass a trailing backslash so the path matches the
	// Win32 GetVolumeInformation contract.
	if d, err := drive.New(`C:\`); err != nil {
		fmt.Printf("drive C: error: %v\n", err)
	} else {
		fmt.Printf("C: letter=%s type=%v\n", d.Letter, d.Type)
	}

	// 5. Known folders (folder.md "Simple — modern KNOWNFOLDERID").
	fmt.Printf("\n=== Known folders ===\n")
	if p, err := folder.GetKnown(windows.FOLDERID_RoamingAppData, 0); err != nil {
		fmt.Printf("RoamingAppData err: %v\n", err)
	} else {
		fmt.Printf("RoamingAppData: %s\n", p)
	}
	if p, err := folder.GetKnown(windows.FOLDERID_LocalAppData, 0); err != nil {
		fmt.Printf("LocalAppData err: %v\n", err)
	} else {
		fmt.Printf("LocalAppData: %s\n", p)
	}
	if p, err := folder.GetKnown(windows.FOLDERID_System, 0); err != nil {
		fmt.Printf("System err: %v\n", err)
	} else {
		fmt.Printf("System: %s\n", p)
	}

	// 6. Network interface IPs (network.md "Simple").
	fmt.Printf("\n=== Network ===\n")
	ips, err := network.InterfaceIPs()
	if err != nil {
		fmt.Printf("InterfaceIPs err: %v\n", err)
	}
	for _, ip := range ips {
		fmt.Printf("ip: %s\n", ip)
	}

	// 7. Hardware breakpoint scan (hw-breakpoints.md "Simple").
	fmt.Printf("\n=== HW breakpoints ===\n")
	bps, err := hwbp.Detect()
	if err != nil {
		fmt.Printf("hwbp.Detect err: %v\n", err)
	}
	if len(bps) == 0 {
		fmt.Printf("no DR0-DR3 set on any thread\n")
	} else {
		for _, bp := range bps {
			// DOC-DRIFT (hw-breakpoints.md): doc references bp.Module + bp.TID
			// — those don't compile. Print the real struct via %+v until the
			// doc is fixed.
			fmt.Printf("breakpoint: %+v\n", bp)
		}
	}
}
