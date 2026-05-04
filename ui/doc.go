//go:build windows

// Package ui exposes minimal Windows UI primitives — `MessageBoxW` via
// `Show` and the system alert sound via `Beep`.
//
// `Show` accepts strongly-typed enums for button set, icon, default
// button, and modality so callers don't pass raw `MB_*` flag values.
// Returns the user's selected `Response` (e.g., `IDOK`, `IDYES`).
//
// `Beep` plays the standard Windows notification sound via
// `MessageBeep(MB_OK)`.
//
// Useful for:
//
//   - Implant lifecycle prompts during red-team exercises ("Operator
//     ready?").
//   - Honey-pot-style decoy dialogs.
//   - Sandbox-evasion: humans dismiss dialogs; sandboxes generally
//     don't (paired with [github.com/oioio-space/maldev/recon/sandbox]).
//
// # MITRE ATT&CK
//
// N/A (UI utility).
//
// # Detection level
//
// very-quiet
//
// `MessageBoxW` is the most-used Windows API; no signal.
//
// # Required privileges
//
// unprivileged for the implant's own interactive
// session. `MessageBoxW` and `MessageBeep` render to
// the calling process's window station; SYSTEM in
// session 0 has no interactive desktop and dialogs
// stay invisible (the call still returns a default
// response immediately).
//
// # Platform
//
// Windows-only (`//go:build windows`). user32
// `MessageBoxW` + `MessageBeep`; no POSIX equivalent.
//
// # Example
//
// See [ExampleShow] and [ExampleBeep] in ui_example_test.go.
//
// # See also
//
//   - [github.com/oioio-space/maldev/recon/sandbox] — pair with prompt-style sandbox detection
//
// [github.com/oioio-space/maldev/recon/sandbox]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/sandbox
package ui
