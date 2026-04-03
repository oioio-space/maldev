//go:build windows

// Package impersonate provides Windows thread impersonation utilities
// for executing code under alternate user credentials.
//
// Technique: Thread-level token impersonation for lateral movement and
// privilege escalation.
// MITRE ATT&CK: T1134.001 (Token Impersonation/Theft).
// Detection: Medium — impersonation events are logged in the Security event log
// (Event ID 4648 for explicit credential use).
// Platform: Windows.
//
// How it works: LogonUserW authenticates credentials via advapi32 and returns
// a token handle. ImpersonateLoggedOnUser sets the calling thread's security
// context to that token. ImpersonateThread combines both in a safe pattern:
// it locks the OS thread, impersonates, runs a user callback, then reverts
// via RevertToSelf on a deferred cleanup path.
//
// Limitations:
//   - ImpersonateThread requires the calling goroutine to NOT be shared
//     with other goroutines (handled internally via LockOSThread).
//   - Network logon (type 3) tokens cannot access local resources.
//   - Requires SeImpersonatePrivilege or equivalent.
//
// Example:
//
//	impersonate.ImpersonateThread(false, ".", "user", "pass", func() error {
//	    // Code here runs as "user"
//	    return nil
//	})
package impersonate
