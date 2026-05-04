// Package clr hosts the .NET Common Language Runtime in process
// via the `ICLRMetaHost` / `ICorRuntimeHost` COM interfaces and
// executes managed assemblies from memory without writing them
// to disk.
//
// `CLRCreateInstance` (mscoree.dll) yields an `ICLRMetaHost`.
// Enumerate installed runtimes; pick the preferred version
// (v4 > any). `GetInterface(CLSID_CLRRuntimeHost,
// IID_ICorRuntimeHost)` returns an `ICorRuntimeHost`; `Start`
// transitions it to Started; `GetDefaultDomain` gives the
// default AppDomain as an `IUnknown` which is queried for
// `IDispatch`; `Load_3(SAFEARRAY[byte])` loads the assembly;
// `EntryPoint.Invoke` runs it.
//
// Hostile assemblies require an upstream AMSI patch — call
// `evasion/amsi.PatchAll` before `ExecuteAssembly` or any
// flagged bytes (SharpHound, Rubeus, Seatbelt) hit
// `AmsiScanBuffer` and get blocked.
//
// .NET 3.5 (legacy) hosting requires
// [InstallRuntimeActivationPolicy] first to register the
// CLSID — disabled by default on modern Windows. The package
// returns [ErrLegacyRuntimeUnavailable] when the legacy runtime
// is missing.
//
// References (mined for technique only):
//
//   - ropnop/go-clr — canonical Go port; [vendored upstream].
//
// # MITRE ATT&CK
//
//   - T1620 (Reflective Code Loading) — CLR-hosted .NET assembly load
//   - T1059 (Command and Scripting Interpreter) — in-memory script-language execution
//
// # Detection level
//
// moderate
//
// Loading the CLR inside a non-.NET host process is a strong
// heuristic signal (`clr.dll` + `mscoreei.dll` module load).
// AMSI v2 scans every assembly passed to `AppDomain.Load_3`.
// ETW Microsoft-Windows-DotNETRuntime emits assembly-load
// events. Pair with [github.com/oioio-space/maldev/evasion/amsi]
// + [github.com/oioio-space/maldev/evasion/etw] for full
// silencing.
//
// # Required privileges
//
// unprivileged. CLR hosting + assembly load + entry-
// point invoke all run in the calling process's
// address space — `CLRCreateInstance` and the COM
// interfaces (`ICLRMetaHost`, `ICorRuntimeHost`,
// `AppDomain`) are user-mode APIs. The loaded
// managed code's privilege gate matches its native
// equivalent: a SharpHound-equivalent enumerator
// against AD needs the user's domain rights;
// SeManageVolumePrivilege-style work needs admin.
//
// # Platform
//
// Windows-only. Hosts the .NET Framework CLR via
// mscoree.dll — Microsoft's Windows-only runtime.
// .NET Core / .NET 5+ uses a different hosting API
// (`hostfxr` / `nethost`) not yet wired up; pure
// Linux .NET execution is out of scope.
//
// # Example
//
// See [ExampleLoad] in clr_example_test.go.
//
// # See also
//
//   - docs/techniques/runtime/clr.md
//   - [github.com/oioio-space/maldev/runtime/bof] — sibling reflective runtime (COFF)
//   - [github.com/oioio-space/maldev/evasion/amsi] — AMSI patch (required for hostile assemblies)
//   - [github.com/oioio-space/maldev/evasion/etw] — ETW patch (.NET runtime telemetry)
//
// [github.com/oioio-space/maldev/runtime/bof]: https://pkg.go.dev/github.com/oioio-space/maldev/runtime/bof
// [github.com/oioio-space/maldev/evasion/amsi]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/amsi
// [github.com/oioio-space/maldev/evasion/etw]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/etw
package clr
