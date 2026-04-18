// Package pe provides Portable Executable analysis and manipulation utilities.
//
// Technique: PE file parsing, stripping, reflective loading, and signing tricks.
// MITRE ATT&CK: T1027.002 (Obfuscated Files: Software Packing), T1055.001
// (Reflective Code Loading), T1553.002 (Code Signing)
// Platform: Cross-platform parsing; Windows-specific loaders.
// Detection: Varies by sub-package, typically Low-to-Medium.
//
// This is the parent umbrella. Import one of:
//
//   - pe/parse:      read-only PE parsing (debug/pe wrapper)
//   - pe/strip:      remove Go toolchain artifacts (pclntab, sections, timestamps)
//   - pe/morph:      UPX-style mutation of PE sections
//   - pe/imports:    enumerate import tables for API-resolution payloads
//   - pe/srdi:       Donut-compatible shellcode conversion
//   - pe/bof:        minimal COFF (Beacon Object File) loader
//   - pe/cert:       Authenticode certificate read/copy/strip/write
//   - pe/clr:        .NET CLR in-process hosting
//   - pe/masquerade: process argv0 / PEB masquerading presets
//
// The umbrella package exports nothing; each sub-package has its own doc.go
// with MITRE coverage and a usage example.
package pe
