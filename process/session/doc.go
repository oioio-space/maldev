//go:build windows

// Package session provides utilities for executing processes and impersonating
// threads in other user sessions on Windows.
//
// Technique: Cross-session process creation and thread impersonation.
// MITRE ATT&CK: T1134.002 (Access Token Manipulation: Create Process with Token)
// Platform: Windows
// Detection: Medium -- cross-session process creation is logged in Security event log.
//
// Key features:
//   - CreateProcessOnActiveSessions: create a process under another user's token
//     with proper environment block and working directory
//   - ImpersonateThreadOnActiveSession: run a callback on a locked OS thread
//     under alternate credentials, reverting automatically on completion
package session
