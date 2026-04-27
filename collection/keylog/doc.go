//go:build windows

// Package keylog captures keystrokes via a low-level keyboard hook
// (`SetWindowsHookEx(WH_KEYBOARD_LL)`).
//
// `Start(ctx)` installs the hook and returns a channel of Event
// records. Each event includes the virtual-key code, translated
// character (or `[Enter]` / `[Backspace]` label), modifier flags,
// foreground-window title, and owning-process executable path. The
// message loop runs on a locked OS thread and tears down when the
// context is cancelled.
//
// # MITRE ATT&CK
//
//   - T1056.001 (Input Capture: Keylogging)
//
// # Detection level
//
// noisy
//
// `SetWindowsHookEx(WH_KEYBOARD_LL)` is one of the highest-fidelity
// behavioural signals EDR products track — almost no benign software
// installs a global low-level keyboard hook.
//
// # Example
//
// See [ExampleStart] in keylog_example_test.go.
//
// # See also
//
//   - docs/techniques/collection/keylogging.md
package keylog
