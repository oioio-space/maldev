//go:build windows

// Package token provides Windows token manipulation utilities for
// querying and modifying process and thread security tokens.
//
// Platform: Windows
// Detection: Medium -- token manipulation is monitored by EDR products.
//
// Key features:
//   - Open and duplicate process tokens (primary, impersonation, linked)
//   - Enable, disable, and remove individual or all token privileges
//   - Query token integrity level (Low/Medium/High/System)
//   - Retrieve user details (username, domain, profile directory)
//   - Obtain interactive session tokens via WTSQueryUserToken
//
// Ported from github.com/FourCoreLabs/wintoken with additional features.
package token
