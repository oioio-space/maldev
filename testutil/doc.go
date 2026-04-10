// Package testutil provides shared test helpers for the maldev project.
//
// Technique: N/A (test infrastructure).
// MITRE ATT&CK: N/A.
// Detection: N/A.
// Platform: Cross-platform (with Windows-specific helpers gated by build tags).
//
// Helpers include payload loading, sacrificial process spawning, platform
// skip guards, and shellcode generation for integration tests.
package testutil
