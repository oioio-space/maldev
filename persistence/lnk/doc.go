// Package lnk creates Windows shortcut (.lnk) files via COM/OLE
// automation — fluent builder API, fully Windows-only.
//
// Initialises a single-threaded COM apartment, instantiates
// `WScript.Shell`, calls `CreateShortcut` to obtain an
// `IWshShortcut` dispatch interface, sets properties (target,
// arguments, icon, working dir, window style) via
// `IDispatch::PutProperty`, and persists the .lnk to disk via
// `Save`. The COM apartment is torn down after each `Save`.
//
// Used directly by [github.com/oioio-space/maldev/persistence/startup]
// to drop StartUp-folder shortcuts; can also be invoked
// standalone to plant LNKs in user-frequented paths
// (Desktop, Documents, Quick Launch) for T1204.002 user
// execution.
//
// # MITRE ATT&CK
//
//   - T1547.009 (Boot or Logon Autostart Execution: Shortcut Modification)
//   - T1204.002 (User Execution: Malicious File) — when the LNK is dropped in user-traversed paths
//
// # Detection level
//
// quiet
//
// LNK files are normal Windows artefacts — every Office install,
// every Windows update, every user-double-click on a target
// generates them. EDRs that watch LNK creation in StartUp
// folders specifically (path-scoped rules) flag the persistence
// case; standalone LNK creation elsewhere is rarely scrutinised.
//
// # Example
//
// See [ExampleNew] in lnk_example_test.go.
//
// # See also
//
//   - docs/techniques/persistence/lnk.md
//   - [github.com/oioio-space/maldev/persistence/startup] — primary consumer (StartUp-folder persistence)
//   - [github.com/oioio-space/maldev/cleanup] — remove LNK artefacts post-op
//
// [github.com/oioio-space/maldev/persistence/startup]: https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup
// [github.com/oioio-space/maldev/cleanup]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup
package lnk
