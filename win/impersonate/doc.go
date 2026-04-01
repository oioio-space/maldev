//go:build windows

// Package impersonate provides Windows thread impersonation utilities
// for executing code under alternate user credentials.
//
// Platform: Windows
// Detection: Medium -- impersonation events are logged in Security event log.
//
// Key features:
//   - LogonUserW wrapper for authenticating with domain or local credentials
//   - ImpersonateLoggedOnUser wrapper for thread-level impersonation
//   - ImpersonateThread helper that runs a callback under alternate credentials
//     on a locked OS thread, automatically reverting to self on completion
//   - ThreadEffectiveTokenOwner to query the impersonated identity
package impersonate
