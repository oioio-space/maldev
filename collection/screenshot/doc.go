//go:build windows

// Package screenshot captures the screen via GDI `BitBlt` and returns
// PNG bytes.
//
// Single-monitor: `Capture` (primary display) or `CaptureRect(x, y,
// w, h)`. Multi-monitor: `DisplayCount` enumerates,
// `DisplayBounds(idx)` reports the rectangle, `CaptureDisplay(idx)`
// targets a specific monitor.
//
// # MITRE ATT&CK
//
//   - T1113 (Screen Capture)
//
// # Detection level
//
// quiet
//
// GDI operations are high-volume legitimate APIs. Frequency-based
// detection (one screenshot per minute is normal; one per second is
// not) is the typical signal.
//
// # Required privileges
//
// unprivileged for the implant's own interactive session — GDI
// `BitBlt` against the screen DC reads the pixels the implant's
// session can see. SYSTEM in session 0 captures a black image
// from the implant's session unless `process/session` first
// attaches the user's desktop. Capturing across sessions
// requires impersonating a user with that session active.
//
// # Platform
//
// Windows-only (`//go:build windows`). Sits on the GDI surface
// (`gdi32!BitBlt`, `user32!GetDC`); other OSes need `Quartz` /
// `XComposite` / Wayland-shot which are not wired up.
//
// # Example
//
// See [ExampleCapture] and [ExampleCaptureDisplay] in
// screenshot_example_test.go.
//
// # See also
//
//   - docs/techniques/collection/screenshot.md
package screenshot
