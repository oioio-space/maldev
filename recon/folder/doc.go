// Package folder resolves Windows special folder paths via
// `SHGetSpecialFolderPathW` (Shell32) — Desktop, AppData,
// Startup, Program Files, Common AppData, etc.
//
// Single entry point: [Get] takes a [CSIDL] constant and an
// optional create-if-missing flag, returns the resolved
// filesystem path. The OS handles per-user vs per-machine
// path differences and folder redirection in domain
// environments transparently.
//
// Used by `persistence/startup` to resolve `%APPDATA%\…\Startup`
// and `%PROGRAMDATA%\…\StartUp`, by `credentials/lsassdump` to
// resolve `%SystemRoot%\System32\ntoskrnl.exe` for
// EPROCESS-offset discovery, and by any payload that needs to
// write into a per-user / per-machine well-known location.
//
// # MITRE ATT&CK
//
//   - T1083 (File and Directory Discovery)
//
// # Detection level
//
// very-quiet
//
// `SHGetSpecialFolderPathW` is one of the most-called Shell32
// APIs on a typical desktop — every installer, every Office
// app, every browser invokes it continuously.
//
// # Example
//
// See [ExampleGet] in folder_example_test.go.
//
// # See also
//
//   - docs/techniques/recon/folder.md
//   - [github.com/oioio-space/maldev/persistence/startup] — primary consumer (StartUp folder resolution)
//   - [github.com/oioio-space/maldev/recon/drive] — sibling filesystem discovery
//
// [github.com/oioio-space/maldev/persistence/startup]: https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup
// [github.com/oioio-space/maldev/recon/drive]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/drive
package folder
