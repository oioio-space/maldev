//go:build windows

// Package clipboard reads and watches the Windows clipboard text.
//
// `ReadText` returns the current clipboard text in one call.
// `Watch(ctx, interval)` polls the clipboard sequence number and
// streams text changes through a channel until the context is
// cancelled — useful for keylog-adjacent collection where the user
// pastes credentials.
//
// # MITRE ATT&CK
//
//   - T1115 (Clipboard Data)
//
// # Detection level
//
// quiet
//
// `OpenClipboard` is high-volume legitimate API. `Watch` produces a
// steady poll cadence — frequency-based hunts can flag unusually high
// poll rates.
//
// # Example
//
// See [ExampleReadText] in clipboard_example_test.go.
//
// # See also
//
//   - docs/techniques/collection/clipboard.md
package clipboard
