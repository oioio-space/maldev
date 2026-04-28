//go:build windows

package privilege_test

import (
	"context"
	"fmt"

	"github.com/oioio-space/maldev/win/privilege"
)

// IsAdmin returns both the "in Administrators group" and "token is
// elevated" answers — the second is what gates UAC-relevant flows.
func ExampleIsAdmin() {
	admin, elevated, err := privilege.IsAdmin()
	if err != nil {
		fmt.Println("admin:", err)
		return
	}
	fmt.Printf("admin=%t elevated=%t\n", admin, elevated)
}

// ExecAs spawns a command under alternate credentials via LogonUserW
// + token-based exec.Cmd. Caller drives the lifecycle with normal
// *exec.Cmd ergonomics (Stdout pipe, Wait, ctx cancel).
func ExampleExecAs() {
	ctx := context.Background()
	cmd, err := privilege.ExecAs(ctx, false, ".", "user", "pass",
		`C:\Windows\System32\cmd.exe`, "/c", "whoami")
	if err != nil {
		fmt.Println("exec:", err)
		return
	}
	_ = cmd.Wait()
}
