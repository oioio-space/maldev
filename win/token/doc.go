//go:build windows

// Package token provides Windows token manipulation utilities for
// querying and modifying process and thread security tokens.
//
// Technique: Process/thread token theft, duplication, privilege adjustment,
// integrity query, and interactive-session token retrieval.
// MITRE ATT&CK: T1134 (Access Token Manipulation), T1134.001 (Token
// Impersonation/Theft), T1134.002 (Create Process with Token)
// Platform: Windows
// Detection: Medium -- token manipulation is monitored by EDR products via
// OpenProcess + DuplicateTokenEx telemetry; SeDebugPrivilege enablement is
// a common behavioral signal.
//
// Key features:
//   - PID-based token theft via Steal and StealByName (full steal chain)
//   - Open and duplicate process tokens (primary, impersonation, linked)
//   - Enable, disable, and remove individual or all token privileges
//   - Query token integrity level (Low/Medium/High/System)
//   - Retrieve user details (username, domain, profile directory)
//   - Obtain interactive session tokens via WTSQueryUserToken
//
// Ported from github.com/FourCoreLabs/wintoken with additional features.
package token
