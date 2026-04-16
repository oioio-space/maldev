// Package masquerade provides programmatic PE resource extraction and .syso
// generation for identity cloning.
//
// Technique: Extract manifest, icons, version info, and certificate from any
// Windows PE, then generate a linkable .syso COFF object that embeds those
// resources into a Go binary at compile time.
//
// MITRE ATT&CK: T1036.005 — Masquerading: Match Legitimate Name or Location.
// Platform: Cross-platform (operates on PE bytes).
// Detection: Low — VERSIONINFO/manifest can be inspected but rarely are.
//
// Two approaches:
//
// 1. Pre-built presets (zero-effort, no source PE needed at build time):
//
//	import _ "github.com/oioio-space/maldev/pe/masquerade/preset/svchost"
//
// 2. Programmatic API (clone any PE):
//
//	masquerade.Clone(`C:\Windows\System32\svchost.exe`, "resource.syso", masquerade.AMD64, masquerade.AsInvoker)
//
// Composable extraction:
//
//	res, _ := masquerade.Extract(`C:\Windows\System32\svchost.exe`)
//	res.VersionInfo.OriginalFilename = "myservice.exe"
//	res.GenerateSyso("resource.syso", masquerade.AMD64, masquerade.AsInvoker)
package masquerade
