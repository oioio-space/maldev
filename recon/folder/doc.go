// Package folder resolves Windows special folder paths via two
// Shell32 entry points: [Get] (legacy `SHGetSpecialFolderPathW`,
// CSIDL-keyed) and [GetKnown] (modern `SHGetKnownFolderPath`,
// KNOWNFOLDERID-keyed). Microsoft recommends the KNOWNFOLDERID
// path for new code — it returns API-allocated `PWSTR` (not
// `MAX_PATH`-capped), supports 3rd-party Shell extensions that
// register their own folders, and is the only API that exposes
// modern locations like `Downloads`. The CSIDL helper stays for
// backwards compatibility with older callers.
//
// `FOLDERID_*` constants are exported as `windows.GUID` values:
// Profile, Desktop, Documents, Downloads, LocalAppData,
// RoamingAppData, Programs, Startup, System, Windows,
// ProgramFiles, ProgramFilesX86, PublicDesktop, CommonStartup.
// Pass any of them (or your own GUID) to [GetKnown] with an
// optional [KnownFolderFlag] (e.g. `KFF_CREATE` to force
// directory creation, `KFF_DONT_VERIFY` to skip the existence
// check).
//
// The OS handles per-user vs per-machine path differences and
// folder redirection in domain environments transparently for
// both APIs.
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
