// Package multicat provides a multi-session reverse-shell listener
// for operator use. It accepts incoming connections from reverse-shell
// agents (`c2/shell`), assigns each a sequential session ID, and emits
// events over a channel. Sessions are held in memory only — they do
// not survive a manager restart.
//
// Wire protocol (BANNER): when an agent connects, multicat reads the
// first line with a 500 ms deadline. A line of the form
// `BANNER:<hostname>\n` populates `SessionMetadata.Hostname`. All
// other bytes are part of the normal shell I/O stream.
//
// This package is **operator-side only** — it is never embedded in
// the implant.
//
// # MITRE ATT&CK
//
//   - T1571 (Non-Standard Port) — operator listener typically binds
//     a high non-standard port to host the multi-handler
//
// # Detection level
//
// quiet
//
// The package never executes on a target. Network signatures apply
// to the agent side (`c2/shell`); the listener itself is invisible to
// endpoint defenders.
//
// # Required privileges
//
// unprivileged for the typical operator listener on a high
// non-standard port. Privileged ports (< 1024 on POSIX, < 1024
// or reserved-range on Windows) require the platform's
// privileged-port permission.
//
// # Platform
//
// Cross-platform.
//
// # Example
//
// See [ExampleNew] in multicat_example_test.go.
//
// # See also
//
//   - docs/techniques/c2/multicat.md
//   - [github.com/oioio-space/maldev/c2/shell] — agent counterpart
//   - [github.com/oioio-space/maldev/c2/transport] — listener factory
//
// [github.com/oioio-space/maldev/c2/shell]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell
// [github.com/oioio-space/maldev/c2/transport]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport
package multicat
