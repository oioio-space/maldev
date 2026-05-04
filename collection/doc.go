// Package collection groups local data-acquisition primitives for
// post-exploitation: keystrokes, clipboard contents, screen captures.
//
// Each sub-package is self-contained — import the one you need:
//
//   - [github.com/oioio-space/maldev/collection/keylog] —
//     low-level keyboard hook (T1056.001)
//   - [github.com/oioio-space/maldev/collection/clipboard] —
//     OpenClipboard + sequence polling (T1115)
//   - [github.com/oioio-space/maldev/collection/screenshot] —
//     GDI BitBlt multi-monitor capture (T1113)
//
// # MITRE ATT&CK
//
//   - T1056.001 (Input Capture: Keylogging)
//   - T1113 (Screen Capture)
//   - T1115 (Clipboard Data)
//
// # Detection level
//
// varies
//
// Keylog hook is `noisy` (EDR scrutinises `SetWindowsHookEx`).
// Clipboard polling is `quiet`. Screenshot via GDI is `quiet` and
// blends with benign software.
//
// # Required privileges
//
// Per sub-package. `keylog` and `clipboard` are unprivileged
// for the active interactive session — their hooks live in the
// caller's window-station / desktop, so they capture only what
// the implant's session can already see. `screenshot` is
// unprivileged for the same reason; capturing another user's
// session needs SYSTEM + the right session/desktop attach.
// SYSTEM in session 0 captures nothing useful from interactive
// users without `process/session` first switching the desktop.
//
// # Platform
//
// Windows-only across the three sub-packages. Each is gated by
// `//go:build windows` and depends on user32 / gdi32 / WH_*
// hooks that have no cross-platform analogue.
//
// # See also
//
//   - docs/techniques/collection/README.md
//
// [github.com/oioio-space/maldev/collection/keylog]: https://pkg.go.dev/github.com/oioio-space/maldev/collection/keylog
// [github.com/oioio-space/maldev/collection/clipboard]: https://pkg.go.dev/github.com/oioio-space/maldev/collection/clipboard
// [github.com/oioio-space/maldev/collection/screenshot]: https://pkg.go.dev/github.com/oioio-space/maldev/collection/screenshot
package collection
