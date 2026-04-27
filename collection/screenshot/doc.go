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
// # Example
//
// See [ExampleCapture] and [ExampleCaptureDisplay] in
// screenshot_example_test.go.
//
// # See also
//
//   - docs/techniques/collection/screenshot.md
package screenshot
