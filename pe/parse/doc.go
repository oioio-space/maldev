// Package parse provides PE file parsing and modification utilities.
//
// Wraps `github.com/saferwall/pe` with helpers tailored to maldev
// workflows: section enumeration, export resolution, header
// manipulation, and raw byte access for PE morphing and sRDI
// pipelines. The saferwall backend brings native support for the
// Authenticode hash ([File.Authentihash]), Mandiant's import hash
// ([File.ImpHash]), structural anomaly detection
// ([File.Anomalies]), Microsoft Rich header parsing
// ([File.RichHeader]), Overlay / appended-payload detection
// ([File.Overlay]), CFG / dynamic-reloc directories, .NET CLR
// metadata — none of which the stdlib `debug/pe` exposes.
//
// # Constructors
//
//   - [Open] / [FromBytes] — full parse (every PE directory).
//   - [FromBytesFast] — exports + sections only, ~10× faster
//     for hot-path callers (unhook prologue restore, lsassdump
//     EPROCESS-offset discovery). Skips resource / exception /
//     CLR / TLS / load-config / debug / IAT / delay-import /
//     bound-import / reloc directories.
//   - [OpenStealth] / [OpenStealthFast] — read through a
//     [stealthopen.Opener] (NTFS Object ID etc.) before parsing.
//
// # Per-export accessors
//
//   - [File.ExportRVA] — function-body RVA by name (forwarder-aware).
//   - [File.DataAtRVA] — section-walking RVA → file-offset → bytes.
//   - [File.ExportEntries] / [File.Exports] — full / names-only.
//   - [File.SectionByName] / [File.SectionData] /
//     [File.SectionBytes] — section access by name.
//   - [File.Imports] — flat DLL list (use sibling `pe/imports`
//     for per-function detail + delay-load coverage).
//
// # Saferwall capability surfaces
//
//   - [File.Authentihash] — SHA-256 over the canonical
//     Authenticode-signed PE bytes. Match against
//     `SpcIndirectDataContent`'s digest to verify post-sign
//     tampering.
//   - [File.ImpHash] — Mandiant's lowercased imphash, MD5 over
//     the joined `<dll>.<func>` import list.
//   - [File.Anomalies] — structural-oddity list (overlapping
//     headers, malformed directories, suspicious section sizes).
//   - [File.RichHeader] — MSVC linker bill-of-materials.
//     Strongest single fingerprint of the build pipeline.
//   - [File.Overlay] / [File.OverlayOffset] — bytes appended past
//     the last section (droppers stage payloads here, signed PEs
//     surface their WIN_CERTIFICATE blob).
//
// The package operates on bytes only; every entry point accepts a
// path or a `[]byte`, so analysts can inspect Windows PEs from any
// host.
//
// # MITRE ATT&CK
//
//   - T1027.002 (Obfuscated Files or Information: Software Packing) — discovery primitive consumed by pe/strip + pe/morph
//
// # Detection level
//
// very-quiet
//
// Offline analysis only — no syscalls, no file opens beyond the
// caller-supplied reader. The package is invisible to runtime
// telemetry.
//
// # Required privileges
//
// unprivileged. Pure-Go saferwall walker over caller-supplied
// bytes; only the read DACL on the source path applies.
//
// # Platform
//
// Cross-platform. saferwall runs everywhere — analysts can
// dissect Windows PEs from Linux / macOS / CI without a Windows
// host.
//
// # Example
//
// See [ExampleOpen] in parse_example_test.go.
//
// # See also
//
//   - docs/techniques/pe/README.md
//   - [github.com/oioio-space/maldev/pe/strip] — primary consumer for Go-binary sanitisation
//   - [github.com/oioio-space/maldev/pe/morph] — primary consumer for UPX morphing
//   - [github.com/oioio-space/maldev/pe/imports] — sibling import-table analyser
//
// [github.com/oioio-space/maldev/pe/strip]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/strip
// [github.com/oioio-space/maldev/pe/morph]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/morph
// [github.com/oioio-space/maldev/pe/imports]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/imports
package parse
