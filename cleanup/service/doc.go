//go:build windows

// Package service provides Windows service hiding via DACL (Discretionary
// Access Control List) manipulation to restrict service visibility.
//
// Technique: Apply restrictive security descriptors to Windows services.
// MITRE ATT&CK: T1564.005 (Hide Artifacts: Hidden File System)
// Platform: Windows
// Detection: Medium -- DACL changes on services are logged if auditing is enabled.
//
// Two application modes:
//   - NATIF: uses SetNamedSecurityInfo Windows API directly
//   - SC_SDSET: uses sc.exe SDSET command (works remotely with hostname)
//
// HideService applies a DACL that denies interactive/service/admin users
// most access while allowing minimal read access. UnHideService restores
// the default DACL.
package service
