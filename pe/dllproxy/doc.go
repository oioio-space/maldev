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
// With [Options.PayloadDLL] empty (the default), the emitter produces
// a forwarder-only PE — no DllMain, no imports, invisible at runtime
// once loaded; the real target executes as if loaded directly.
//
// With [Options.PayloadDLL] set, the emitter additionally embeds a
// small DllMain stub (32 bytes on AMD64, 28 bytes on I386) plus an
// import directory referencing kernel32!LoadLibraryA. On
// DLL_PROCESS_ATTACH the stub calls `LoadLibraryA(payload)` and
// returns TRUE — the loader pulls the extra DLL into the victim
// process before user code resumes.
//
// Both PE32 (32-bit, [MachineI386]) and PE32+ (64-bit,
// [MachineAMD64], default) outputs are supported. The 32-bit path is
// for hijacking legacy WOW64 victims — same forwarder semantics, same
// payload-loader contract, different optional-header layout and
// stdcall-flavoured stub.
//
// # Composition
//
// The natural pipeline is:
//
//   - Discover an opportunity via [recon/dllhijack].
//   - Read the target DLL's exports via [pe/parse.File.Exports]
//     (names only) or [pe/parse.File.ExportEntries] (names + ordinals
//     + forwarders — required when the target ships ordinal-only
//     exports such as msvcrt or ws2_32).
//   - Hand them to [Generate] (string names) or [GenerateExt] (rich
//     [Export] entries) together with the target's filename.
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
// # Required privileges
//
// unprivileged for the emitter — pure-byte assembly of a PE
// in memory; no syscall, no token. The deployment side
// inherits the DACL of the chosen HijackedPath: user-writable
// paths (per-user `%LOCALAPPDATA%\…`, third-party app dirs)
// work in any token; system-protected paths
// (`C:\Windows\System32\`, `C:\Program Files\…`) require
// admin to drop the proxy.
//
// # Platform
//
// Cross-platform emitter (pure-Go PE assembly). The produced
// DLL only loads on Windows; the technique itself is
// Windows-only at runtime. PE32 + PE32+ outputs are both
// supported, so a Linux operator can stage either WOW64 or
// 64-bit hijack payloads from CI.
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
