//go:build windows

// persistence-admin — panorama 6 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/persistence/user.md   — local account creation
//   - docs/techniques/persistence/service.md   — SCM service install
//   - docs/techniques/persistence/lnk.md       — Desktop launcher
//
// Tests the three privileged persistence vectors. account + service
// expect admin; lnk works for any user able to write to the target
// directory (so an admin can drop into Public, lowuser can drop into
// its own desktop). Each install paired with a teardown so the
// example doesn't pollute repeat matrix runs.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	user "github.com/oioio-space/maldev/persistence/account"
	"github.com/oioio-space/maldev/persistence/lnk"
	"github.com/oioio-space/maldev/persistence/service"
)

func main() {
	// 1. Local account (user.md "Simple" — package alias `user`).
	fmt.Printf("=== Account ===\n")
	if err := user.Add("svc-update-test", "P@ssw0rd!2026"); err != nil {
		fmt.Printf("user.Add: %v\n", err)
	} else {
		fmt.Printf("user.Add: OK\n")
		if err := user.Delete("svc-update-test"); err != nil {
			fmt.Printf("user.Delete: %v\n", err)
		} else {
			fmt.Printf("user.Delete: OK\n")
		}
	}

	// 2. SCM service (service.md "Simple"). Auto-start, manual cleanup.
	fmt.Printf("\n=== Service ===\n")
	cfg := &service.Config{
		Name:        "WinUpdateNotifierTest",
		DisplayName: "Windows Update Notification Center (TEST)",
		Description: "Test service installed by maldev panorama 6.",
		BinPath:     `C:\Windows\System32\cmd.exe`,
		StartType:   service.StartAuto,
	}
	if err := service.Install(cfg); err != nil {
		fmt.Printf("service.Install: %v\n", err)
	} else {
		fmt.Printf("service.Install: OK\n")
		if err := service.Uninstall("WinUpdateNotifierTest"); err != nil {
			fmt.Printf("service.Uninstall: %v\n", err)
		} else {
			fmt.Printf("service.Uninstall: OK\n")
		}
	}

	// 3. .lnk on the user's Desktop (lnk.md "Simple"). Use the running
	//    user's Public Desktop fallback so admin + lowuser both have
	//    something to write to without resolving SHGetKnownFolderPath
	//    (which fails for lowuser per panorama 5's findings).
	fmt.Printf("\n=== LNK launcher ===\n")
	target := filepath.Join(os.Getenv("PUBLIC"), "Desktop", "panorama6-link.lnk")
	if err := lnk.New().
		SetTargetPath(`C:\Windows\System32\cmd.exe`).
		SetArguments("/c whoami").
		SetWindowStyle(lnk.StyleMinimized).
		Save(target); err != nil {
		fmt.Printf("lnk.Save: %v\n", err)
	} else {
		fmt.Printf("lnk.Save: OK at %s\n", target)
		_ = os.Remove(target)
		fmt.Printf("lnk cleanup: OK\n")
	}
}
