// Package acg provides Arbitrary Code Guard (ACG) process mitigation policy
// management for preventing dynamic code generation.
//
// Technique: SetProcessMitigationPolicy with ProcessDynamicCodePolicy.
// MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
// Platform: Windows (10 1709+)
// Detection: Low -- ACG is a legitimate security hardening feature.
//
// When enabled, ACG prevents the process from generating new executable code
// at runtime, which can be used defensively or to interfere with certain
// security products that inject dynamic code.
package acg
