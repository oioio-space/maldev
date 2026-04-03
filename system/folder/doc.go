// Package folder provides access to Windows special folder paths via the
// SHGetSpecialFolderPath Shell32 API.
//
// Technique: Special folder path resolution for payload staging, persistence,
// and environment discovery.
// MITRE ATT&CK: T1083 (File and Directory Discovery)
// Detection: Low — querying special folder paths is standard system behavior.
// Platform: Windows.
//
// How it works: Calls SHGetSpecialFolderPathW with a CSIDL constant to resolve
// the full filesystem path of a Windows special folder (Desktop, AppData,
// Startup, Program Files, etc.). The OS handles per-user and per-machine
// path differences, including folder redirection in domain environments.
//
// Limitations:
//   - SHGetSpecialFolderPathW is deprecated by Microsoft in favor of
//     SHGetKnownFolderPath (Vista+), but remains widely supported and
//     avoids COM initialization overhead.
//   - Some virtual folders (CSIDL_NETWORK, CSIDL_PRINTERS) do not map
//     to filesystem paths and return empty strings.
//
// Example:
//
//	appdata := folder.Get(folder.CSIDL_APPDATA, false)
//	startup := folder.Get(folder.CSIDL_STARTUP, false)
package folder
