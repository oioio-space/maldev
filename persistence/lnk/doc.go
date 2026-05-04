// Package lnk creates Windows shortcut (.lnk) files via COM/OLE
// automation — fluent builder API, fully Windows-only.
//
// Initialises a single-threaded COM apartment and offers three
// serialisation sinks:
//
//   - [Shortcut.Save] — disk persistence via `WScript.Shell` /
//     `IWshShortcut::Save(path)`.
//   - [Shortcut.BuildBytes] — zero-disk; returns raw LNK bytes
//     via `IShellLinkW` + `IPersistStream::Save` on a memory
//     `IStream` (`CreateStreamOnHGlobal`). No filesystem call.
//   - [Shortcut.WriteTo] — same zero-disk path streamed to any
//     `io.Writer` (encrypted ADS, in-memory mount, custom
//     anti-EDR Opener, C2 transport).
//
// The COM apartment is torn down after each call.
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
// # Required privileges
//
// unprivileged. COM apartment init + IShellLinkW marshalling
// run in any token. `Save(path)` inherits the DACL of the
// target directory — user-writable paths (Desktop, %APPDATA%,
// per-user StartUp) work for any user; machine-wide paths
// (`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`,
// `C:\Windows\System32\`) require admin to write. `BuildBytes`
// / `WriteTo` need no filesystem privilege at all — the byte
// destination is operator-controlled.
//
// # Platform
//
// Windows-only. Sits on COM (`Schedule.Service`-style
// IShellLinkW) and `IPersistStream`; no POSIX equivalent.
// Build tags enforce `windows`; cross-compile yields a build
// error.
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
