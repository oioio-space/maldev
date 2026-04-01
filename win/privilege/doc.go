//go:build windows

// Package privilege provides helpers for querying and obtaining elevated
// Windows privileges including administrator detection and RunAs execution.
//
// Platform: Windows
// Detection: Medium -- privilege checks are benign but RunAs/logon actions are logged.
//
// Key features:
//   - Check if current user is an Administrators group member
//   - Check if process is running elevated
//   - Execute processes as another user via SysProcAttr token
//   - Execute processes via CreateProcessWithLogonW
//   - UAC elevation via ShellExecuteW with "runas" verb
package privilege
