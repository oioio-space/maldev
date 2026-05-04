// Package srdi converts PE / .NET / script payloads into
// position-independent shellcode via the Donut framework
// (github.com/Binject/go-donut).
//
// Supported input modules:
//
//   - ModuleEXE / ModuleDLL — native Windows PE files. DLL
//     conversion accepts an export name in `Config.Method`.
//   - ModuleNetEXE / ModuleNetDLL — managed (.NET) assemblies.
//     DLL conversion requires `Config.Class` + `Config.Method`.
//   - ModuleVBS / ModuleJS / ModuleXSL — script payloads
//     wrapped in a PowerShell-or-mshta-equivalent runner.
//
// The output is reflective shellcode that resolves its own
// imports, allocates its own backing store, and executes the
// payload entirely in memory. Pair with
// [github.com/oioio-space/maldev/inject] to deliver the bytes
// to a target process via any of the documented injection
// techniques.
//
// References (mined for technique only — vendored go-donut
// implements the loader):
//
//   - https://github.com/Binject/go-donut
//   - https://github.com/TheWover/donut (canonical C reference)
//   - https://github.com/monoxgas/sRDI
//
// # MITRE ATT&CK
//
//   - T1055.001 (Process Injection: Dynamic-link Library Injection) — downstream consumer
//   - T1620 (Reflective Code Loading) — Donut loader stub is a textbook reflective loader
//
// # Detection level
//
// moderate
//
// Memory scanners that fingerprint the Donut loader stub
// (consistent decoder prologue + module-table layout) flag the
// shellcode at rest in process memory. Pair with
// [github.com/oioio-space/maldev/crypto] payload encryption +
// [github.com/oioio-space/maldev/inject]'s sleep masking to
// hide the stub when not actively executing.
//
// # Required privileges
//
// unprivileged. Donut conversion is offline byte assembly +
// AES-CTR encryption — no syscall, no token. The DACL on
// source PE / output destination is the only upstream gate.
// Privilege requirements only re-emerge at execution time
// when `inject/*` delivers the produced shellcode to a
// target process.
//
// # Platform
//
// Cross-platform converter (pure-Go go-donut + crypto/aes).
// The produced reflective-loader shellcode runs on Windows
// only; analysts on Linux can stage payloads from CI without
// a Windows host.
//
// # Example
//
// See [ExampleConvertFile] and [ExampleConvertBytes] in
// srdi_example_test.go.
//
// # See also
//
//   - docs/techniques/pe/pe-to-shellcode.md
//   - [github.com/oioio-space/maldev/inject] — execution surface for the produced shellcode
//   - [github.com/oioio-space/maldev/crypto] — encrypt payload before conversion
//
// [github.com/oioio-space/maldev/inject]: https://pkg.go.dev/github.com/oioio-space/maldev/inject
// [github.com/oioio-space/maldev/crypto]: https://pkg.go.dev/github.com/oioio-space/maldev/crypto
package srdi
