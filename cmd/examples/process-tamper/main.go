//go:build windows

// process-tamper — panorama 12 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/process/enum.md     — process enumeration
//   - docs/techniques/process/session.md  — interactive session listing
//   - docs/techniques/process/fakecmd.md  — PEB CommandLine spoof (self)
//
// Skips herpaderping (writes a child process — heavyweight for matrix),
// hideprocess (needs a target task-manager PID and admin), and phant0m
// (kills Sysmon — destructive, admin-only). The 3 included primitives
// are read-only or self-modifying, with clear admin/user differential
// expected only on enum (visibility into other-user processes).
package main

import (
	"fmt"

	"github.com/oioio-space/maldev/process/enum"
	"github.com/oioio-space/maldev/process/session"
	"github.com/oioio-space/maldev/process/tamper/fakecmd"
)

func main() {
	// 1. Process enumeration (enum.md "Simple"). Lowuser typically only
	//    sees its own session's processes; admin sees everything.
	fmt.Println("=== process.enum.List ===")
	procs, err := enum.List()
	if err != nil {
		fmt.Printf("List: %v\n", err)
	} else {
		fmt.Printf("List OK: %d processes visible\n", len(procs))
		// Highlight a few well-known SYSTEM-owned processes to surface
		// the visibility delta.
		watch := map[string]bool{"lsass.exe": true, "winlogon.exe": true,
			"smss.exe": true, "csrss.exe": true, "services.exe": true}
		for _, p := range procs {
			if watch[p.Name] {
				fmt.Printf("  PID=%d PPID=%d Name=%s\n", p.PID, p.PPID, p.Name)
			}
		}
	}

	// 2. Interactive session listing (session.md "Simple").
	fmt.Println("\n=== session.Active ===")
	if infos, err := session.Active(); err != nil {
		fmt.Printf("Active: %v\n", err)
	} else {
		fmt.Printf("Active OK: %d sessions\n", len(infos))
		// DOC-DRIFT (session.md): doc shows SessionID + Username but neither
		// compiles; print the real struct via %+v.
		for _, i := range infos {
			fmt.Printf("  %+v\n", i)
		}
	}

	// 3. PEB CommandLine spoof (fakecmd.md "Simple"). Process-local —
	//    rewrites our OWN PEB.ProcessParameters.CommandLine. Admin not
	//    required since we're touching our own memory.
	fmt.Println("\n=== fakecmd.Spoof (self PEB) ===")
	fake := `C:\Windows\System32\svchost.exe -k netsvcs`
	if err := fakecmd.Spoof(fake, nil); err != nil {
		fmt.Printf("Spoof: %v\n", err)
	} else {
		fmt.Printf("Spoof: OK (PEB now reads as %q)\n", fake)
		if err := fakecmd.Restore(); err != nil {
			fmt.Printf("Restore: %v\n", err)
		} else {
			fmt.Printf("Restore: OK\n")
		}
	}
}
