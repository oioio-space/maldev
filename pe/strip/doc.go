// Package strip provides PE binary sanitization to remove Go-specific
// metadata and compilation artifacts that fingerprint the toolchain.
//
// Technique: PE header and section manipulation to defeat static analysis.
// MITRE ATT&CK: T1027.002 (Obfuscated Files or Information: Software Packing)
// Platform: Cross-platform (operates on PE byte slices)
// Detection: Low -- modified headers and wiped metadata are unlikely to
// trigger behavioural detections; static scanners lose Go-specific context.
//
// How it works:
//   - SetTimestamp overwrites IMAGE_FILE_HEADER.TimeDateStamp
//   - WipePclntab zeros the Go pclntab header, breaking tools like redress,
//     GoReSym, and IDA's go_parser plugin
//   - RenameSections renames Go-specific PE sections (.gopclntab, etc.)
//   - Sanitize combines all sanitizations with sensible defaults
//
// Limitations:
//   - Does not strip rich header, debug directory, or build-id
//   - Pclntab wipe only targets Go 1.16+ magic bytes
//   - Functions expect well-formed PE input; malformed data may panic
//
// Example:
//
//	raw, _ := os.ReadFile("implant.exe")
//	clean := strip.Sanitize(raw)
//	os.WriteFile("implant_clean.exe", clean, 0o644)
package strip
