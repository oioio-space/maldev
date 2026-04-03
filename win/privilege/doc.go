//go:build windows

// Package privilege provides helpers for querying and obtaining elevated
// Windows privileges including administrator detection and RunAs execution.
//
// Technique: Privilege detection and elevation via alternate credentials.
// MITRE ATT&CK: T1134 (Access Token Manipulation), T1548.002 (Abuse Elevation).
// Detection: Medium — privilege checks are benign but RunAs/logon actions are
// logged in the Security event log.
// Platform: Windows.
//
// How it works: IsAdmin/IsAdminGroupMember query the current token's group
// membership against the Administrators SID. ExecAs uses LogonUserW to
// create a token under alternate credentials and spawns a process with it.
// CreateProcessWithLogon calls the Win32 API directly for logon+execute.
// ShellExecuteRunAs triggers the UAC elevation prompt.
//
// Limitations:
//   - ExecAs returns *exec.Cmd — caller must call cmd.Wait() to avoid handle leak.
//   - CreateProcessWithLogon requires the Secondary Logon service running.
//   - ShellExecuteRunAs triggers a visible UAC prompt.
//
// Example:
//
//	admin, elevated, _ := privilege.IsAdmin()
//	cmd, _ := privilege.ExecAs(ctx, false, ".", "user", "pass", "cmd.exe")
//	cmd.Wait()
package privilege
