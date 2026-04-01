//go:build windows

// Package folder provides access to Windows special folder paths via the
// SHGetSpecialFolderPath Shell32 API.
//
// Platform: Windows
// Detection: Low -- querying special folder paths is standard behavior.
//
// Exports CSIDL constants for all standard Windows special folders including
// Desktop, AppData, Program Files, System, Startup, and many more.
//
// Example:
//
//	appdata := folder.Get(folder.CSIDL_APPDATA, false)
//	startup := folder.Get(folder.CSIDL_STARTUP, false)
package folder
