// Package cve202430088 implements CVE-2024-30088, a Windows kernel TOCTOU
// race condition in AuthzBasepCopyoutInternalSecurityAttributes that allows
// local privilege escalation to SYSTEM.
//
// CVE:       CVE-2024-30088
// CVSS:      7.0 (High) - Local Privilege Escalation
// Discovery: k0shl (Angelboy) - DEVCORE
// Patch:     KB5039211 - Patch Tuesday June 2024
//
// Affected:
//   - Windows 10 1507-22H2, Windows 11 21H2-23H2
//   - Windows Server 2016, 2019, 2022, 2022 23H2
//   - Before June 2024 Patch Tuesday
//
// WARNING: This exploit may cause a BSOD if the race corrupts kernel
// memory. Use only in authorized penetration testing engagements.
//
// How it works: CVE-2024-30088 is a time-of-check-to-time-of-use (TOCTOU)
// race condition in the kernel function AuthzBasepCopyoutInternalSecurityAttributes.
// The kernel reads a user-mode security descriptor, validates it, then reads
// it again to copy it -- but between the two reads, the attacker flips the
// descriptor to point at a kernel object, causing the kernel to overwrite an
// arbitrary kernel address. This write primitive is leveraged to overwrite the
// current process's token with a SYSTEM token, achieving full privilege
// escalation.
package cve202430088
