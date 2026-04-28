// Package dllproxy emits a valid Windows DLL — as raw bytes, no
// external toolchain — that forwards every named export back to a
// legitimate target DLL. Use it as the payload-write step of the
// DLL-search-order hijack chain whose discovery side lives in
// [github.com/oioio-space/maldev/recon/dllhijack].
//
// The emitted PE is a forwarder-only proxy: each export resolves to
// an absolute path of the form
// `\\.\GLOBALROOT\SystemRoot\System32\<target>.<export>`. Because the
// path is absolute, the proxy DLL does not recurse into itself when
// the loader resolves the forward — the canonical "perfect proxy"
// trick from mrexodia/perfect-dll-proxy.
//
// Phase 1 emits forwarders only, no DllMain — the proxy is invisible
// at runtime once loaded; the real target executes as if loaded
// directly. Phase 2 will add an optional [Options.PayloadDLL] field
// that embeds a `LoadLibraryA(payload)` call in DllMain.
//
// # Composition
//
// The natural pipeline is:
//
//   - Discover an opportunity via [recon/dllhijack].
//   - Read the target DLL's exports via [pe/parse.File.Exports].
//   - Hand them to [Generate] together with the target's filename.
//   - Drop the result at the opportunity's HijackedPath.
//
// # MITRE ATT&CK
//
//   - T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking)
//   - T1574.002 (Hijack Execution Flow: DLL Side-Loading)
//
// # Detection level
//
// very-quiet
//
// The emitter is offline — no syscalls, no file opens beyond the
// caller-supplied buffers. The deployment side (writing the proxy
// to disk + triggering the victim) is moderate, owned by the
// caller and already covered by [recon/dllhijack].
//
// # Example
//
// See [ExampleGenerate] in dllproxy_example_test.go.
//
// # See also
//
//   - docs/techniques/persistence/dll-proxy.md
//   - [github.com/oioio-space/maldev/pe/parse] — extracts the export list
//   - [github.com/oioio-space/maldev/recon/dllhijack] — finds where to deploy
//
// [github.com/oioio-space/maldev/pe/parse]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/parse
// [github.com/oioio-space/maldev/recon/dllhijack]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack
package dllproxy
