// Package pe is the umbrella for Portable Executable analysis,
// manipulation, and conversion utilities.
//
// The package itself ships no exported symbols — implants and
// operator tools import the sub-package they need:
//
//   - pe/parse — read-only PE parsing (debug/pe wrapper) for
//     section enumeration, export resolution, and raw byte access.
//   - pe/imports — cross-platform import-table enumeration for
//     API-resolution payloads.
//   - pe/strip — Go-toolchain artefact removal (pclntab wipe,
//     section rename, timestamp scrub).
//   - pe/morph — UPX header mutation to break automatic unpackers.
//   - pe/srdi — PE/DLL/.NET-to-shellcode conversion via the Donut
//     framework.
//   - pe/cert — Authenticode certificate read/copy/strip/write.
//   - pe/masquerade — programmatic resource extraction + .syso
//     generation for argv0 / VERSIONINFO / icon cloning.
//
// Each sub-package carries its own MITRE ATT&CK coverage and
// detection profile. The runtime-side BOF and CLR loaders live
// under [github.com/oioio-space/maldev/runtime/bof] and
// [github.com/oioio-space/maldev/runtime/clr] respectively — they
// produce or consume PE bytes but are runtime-execution
// concerns, not file-format ones.
//
// # MITRE ATT&CK
//
//   - T1027.002 (Obfuscated Files or Information: Software Packing) — pe/strip, pe/morph
//   - T1055.001 (Process Injection: Dynamic-link Library Injection) — pe/srdi (downstream)
//   - T1106 (Native API) — pe/imports (discovery of resolved APIs)
//   - T1036.005 (Masquerading: Match Legitimate Name or Location) — pe/masquerade
//   - T1553.002 (Subvert Trust Controls: Code Signing) — pe/cert
//
// # Detection level
//
// Varies by sub-package. Static analysis only is N/A;
// certificate / packer manipulation is quiet on the host but
// visible to forensic re-analysis. Each sub-package documents
// its own detection level.
//
// # Example
//
// See [github.com/oioio-space/maldev/pe/strip],
// [github.com/oioio-space/maldev/pe/morph], and
// [github.com/oioio-space/maldev/pe/srdi] for runnable examples.
//
// # See also
//
//   - docs/techniques/pe/README.md
//   - [github.com/oioio-space/maldev/runtime/bof] — COFF (BOF) loader
//   - [github.com/oioio-space/maldev/runtime/clr] — .NET in-process hosting
//   - [github.com/oioio-space/maldev/inject] — pair PE-derived shellcode with an injector
//
// [github.com/oioio-space/maldev/pe/strip]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/strip
// [github.com/oioio-space/maldev/pe/morph]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/morph
// [github.com/oioio-space/maldev/pe/srdi]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi
// [github.com/oioio-space/maldev/runtime/bof]: https://pkg.go.dev/github.com/oioio-space/maldev/runtime/bof
// [github.com/oioio-space/maldev/runtime/clr]: https://pkg.go.dev/github.com/oioio-space/maldev/runtime/clr
// [github.com/oioio-space/maldev/inject]: https://pkg.go.dev/github.com/oioio-space/maldev/inject
package pe
