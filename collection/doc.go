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
// # See also
//
//   - docs/techniques/collection/README.md
//
// [github.com/oioio-space/maldev/collection/keylog]: https://pkg.go.dev/github.com/oioio-space/maldev/collection/keylog
// [github.com/oioio-space/maldev/collection/clipboard]: https://pkg.go.dev/github.com/oioio-space/maldev/collection/clipboard
// [github.com/oioio-space/maldev/collection/screenshot]: https://pkg.go.dev/github.com/oioio-space/maldev/collection/screenshot
package collection
