// Package startup implements StartUp-folder persistence via LNK
// shortcut files — Windows Shell launches every shortcut in the
// folder at user logon.
//
// Drops a `.lnk` file (created via
// [github.com/oioio-space/maldev/persistence/lnk]) into the
// user's or machine-wide StartUp folder:
//
//   - User: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
//   - Machine: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
//
// Machine-wide installation requires elevated privileges; user
// installation runs unprivileged.
//
// # MITRE ATT&CK
//
//   - T1547.001 (Boot or Logon Autostart Execution: Startup Folder)
//   - T1547.009 (Shortcut Modification)
//
// # Detection level
//
// moderate
//
// StartUp folder is monitored by most security products —
// Defender, MDE, Sysinternals Autoruns. EDRs flag LNK creation
// inside the user / machine StartUp paths even when the LNK
// itself looks benign. The user folder draws less default
// scrutiny than the machine-wide folder.
//
// # Example
//
// See [ExampleShortcut] in startup_example_test.go.
//
// # See also
//
//   - docs/techniques/persistence/startup-folder.md
//   - [github.com/oioio-space/maldev/persistence/lnk] — LNK creation primitive
//   - [github.com/oioio-space/maldev/persistence/registry] — sibling autostart mechanism
//   - [github.com/oioio-space/maldev/cleanup] — remove the LNK post-op
//
// [github.com/oioio-space/maldev/persistence/lnk]: https://pkg.go.dev/github.com/oioio-space/maldev/persistence/lnk
// [github.com/oioio-space/maldev/persistence/registry]: https://pkg.go.dev/github.com/oioio-space/maldev/persistence/registry
// [github.com/oioio-space/maldev/cleanup]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup
package startup
