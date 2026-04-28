//go:build windows

package impersonate_test

import (
	"fmt"

	"github.com/oioio-space/maldev/win/impersonate"
)

// ImpersonateThread credentials → impersonation in one call.
// The callback runs under the alternate context with thread
// pinning and deferred RevertToSelf handled internally.
func ExampleImpersonateThread() {
	err := impersonate.ImpersonateThread(false, ".", "user", "pass", func() error {
		// All ops here run as `user`.
		return nil
	})
	if err != nil {
		fmt.Println("impersonate:", err)
	}
}

// GetSystem locates winlogon.exe (SYSTEM-context), duplicates its
// token, and runs the callback as NT AUTHORITY\SYSTEM. Requires the
// caller to already hold SeDebugPrivilege.
func ExampleGetSystem() {
	err := impersonate.GetSystem(func() error {
		// Op runs as SYSTEM.
		return nil
	})
	if err != nil {
		fmt.Println("getsystem:", err)
	}
}

// RunAsTrustedInstaller spawns the supplied command directly under
// the TrustedInstaller service account — no intermediate
// impersonation block, immediate detached *exec.Cmd.
func ExampleRunAsTrustedInstaller() {
	cmd, err := impersonate.RunAsTrustedInstaller(`C:\Windows\System32\cmd.exe`, "/c", "whoami")
	if err != nil {
		fmt.Println("ti:", err)
		return
	}
	_ = cmd.Wait()
}
