// Package startup provides StartUp folder persistence via LNK shortcut files.
//
// Technique: StartUp folder persistence via LNK shortcut files.
// MITRE ATT&CK: T1547.001 (Boot or Logon Autostart Execution: Startup Folder),
// T1547.009 (Shortcut Modification)
// Platform: Windows
// Detection: Medium -- StartUp folder is monitored by security products.
//
// How it works: Places a Windows shortcut (.lnk) file in the user's or
// machine-wide Startup folder. Windows Shell automatically launches all
// shortcuts in these folders at user logon. The shortcut is created using
// COM/OLE automation via the system/lnk package.
//
// The user's Startup folder is located at:
//
//	%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
//
// The machine-wide Startup folder is located at:
//
//	C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
//
// Machine-wide installation requires elevated privileges.
package startup
