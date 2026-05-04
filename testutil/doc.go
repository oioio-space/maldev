// Package testutil provides shared test helpers for the maldev project.
//
// Technique: N/A (test infrastructure).
// MITRE ATT&CK: N/A.
// Detection: N/A.
// Platform: Cross-platform (with Windows-specific helpers gated by build tags).
//
// Helpers include payload loading, sacrificial process spawning, platform
// skip guards, and shellcode generation for integration tests.
//
// # Required privileges
//
// Per helper. Most run unprivileged (caller-supplied
// payload bytes, in-process scans, sacrificial notepad
// spawn). `KaliSSH` / `KaliGenerateShellcode` need
// network reach to the configured Kali host plus its
// SSH credentials. `SpawnSacrificial` /
// `SpawnAndResume` need the user's
// `CreateProcess` privilege (unprivileged for own-user
// spawns).
//
// # Platform
//
// Cross-platform with Windows-specific helpers gated
// by build tags. `CallerMethods`,
// `ScanProcessMemory*`, `ModuleBounds`,
// `WindowsSearchableCanary`, `SpawnSacrificial`,
// `SpawnAndResume`, `SpyOpener` are Windows-only;
// `KaliSSH` / `KaliGenerateShellcode` work from any
// host with SSH client + reachable Kali VM.
package testutil
