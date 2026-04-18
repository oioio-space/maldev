// Package collection provides data collection techniques for post-exploitation.
//
// Technique: Local data acquisition from the compromised host (keystrokes,
// clipboard contents, screen captures).
// MITRE ATT&CK: T1056.001 (Input Capture: Keylogging), T1115 (Clipboard
// Data), T1113 (Screen Capture)
// Platform: Windows (all three sub-packages)
// Detection: Medium-to-High -- keylog hooks are heavily scrutinised by EDR;
// clipboard/screenshot are more common and blend with benign software.
//
// Sub-packages:
//
//   - collection/keylog:     SetWindowsHookEx WH_KEYBOARD_LL (T1056.001)
//   - collection/clipboard:  OpenClipboard + sequence polling (T1115)
//   - collection/screenshot: GDI BitBlt + multi-monitor capture (T1113)
//
// Each sub-package has its own doc.go with explanation, examples, and
// detection notes. Import the one you need.
package collection
