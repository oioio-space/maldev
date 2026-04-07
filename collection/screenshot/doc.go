// Package screenshot captures screen contents via GDI BitBlt.
//
// Technique: Screen capture via GDI BitBlt.
// MITRE ATT&CK: T1113 (Screen Capture)
// Platform: Windows
// Detection: Medium -- GDI operations are common; behavioral detection focuses
// on frequency and process context.
//
// Capture and CaptureRect produce PNG-encoded screenshots of the primary
// display or an arbitrary rectangle. Multi-monitor support is provided
// via EnumDisplayMonitors: CaptureDisplay targets a specific monitor,
// DisplayCount and DisplayBounds enumerate available displays.
package screenshot
