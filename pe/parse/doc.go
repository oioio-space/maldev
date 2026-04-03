// Package parse provides PE file parsing and modification utilities.
//
// Wraps the standard library debug/pe package with helpers for maldev
// operations: section enumeration, export resolution, header manipulation,
// and raw byte access for PE morphing and sRDI workflows.
//
// Technique: PE file analysis and manipulation.
// MITRE ATT&CK: T1027.002 (Obfuscated Files or Information: Software Packing)
// Detection: N/A — offline analysis tool, no runtime footprint.
//
// Platform: Cross-platform (parses Windows PE files on any OS).
package parse
