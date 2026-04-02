//go:build windows

// Package service provides Windows service hiding via DACL (Discretionary
// Access Control List) manipulation to restrict service visibility.
//
// Technique: Apply restrictive security descriptors to Windows services.
// MITRE ATT&CK: T1564 / T1543.003 (Hide Artifacts / Windows Service)
// Platform: Windows
// Detection: Medium -- DACL changes on services are logged if auditing is enabled.
//
// Two application modes:
//   - Native: uses SetNamedSecurityInfo Windows API directly
//   - SC_SDSET: uses sc.exe SDSET command (works remotely with hostname)
//
// HideService applies a DACL that denies interactive/service/admin users
// most access while allowing minimal read access. UnHideService restores
// the default DACL.
//
// Example:
//
//	// Hide a service using native Windows API
//	output, err := service.HideService(service.Native, "", "MyService")
//
//	// Restore default DACL
//	output, err := service.UnHideService(service.Native, "", "MyService")
package service
