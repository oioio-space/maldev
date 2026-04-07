// Package lnk creates Windows shortcut (.lnk) files via COM/OLE automation.
//
// Technique: Windows shortcut (LNK) file creation via COM/OLE.
// MITRE ATT&CK: T1547.009 (Shortcut Modification), T1204.002 (User Execution: Malicious File)
// Detection: Low — LNK files are normal Windows artifacts.
// Platform: Windows.
//
// How it works: Initializes a single-threaded COM apartment, instantiates
// WScript.Shell, and calls its CreateShortcut method to obtain an
// IWshShortcut dispatch interface. Properties (target, arguments, icon, etc.)
// are set via IDispatch::PutProperty, and Save persists the .lnk to disk.
// The COM apartment is torn down after each Save call.
//
// Key features:
//   - Fluent builder API for shortcut construction
//   - Configurable window style (hidden, normal, maximized, minimized)
//   - All COM resources properly released on completion or error
//
// Limitations:
//   - Requires COM initialization — calls runtime.LockOSThread internally.
//   - Windows-only (no cross-platform stub).
//
// Example:
//
//	err := lnk.New().
//	    SetTargetPath(`C:\Windows\System32\cmd.exe`).
//	    SetArguments("/c whoami").
//	    SetWindowStyle(lnk.StyleHidden).
//	    Save(`C:\Users\Public\Desktop\link.lnk`)
package lnk
