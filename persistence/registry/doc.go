// Package registry provides Windows registry Run/RunOnce key persistence.
//
// Technique: Registry Run/RunOnce key persistence.
// MITRE ATT&CK: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)
// Platform: Windows
// Detection: Medium -- Run keys are commonly monitored by EDR.
//
// How it works: Writes a named string value under the Run or RunOnce registry
// key in either HKCU (current user) or HKLM (local machine). The value
// typically contains the full path to an executable. Windows automatically
// launches programs listed in Run keys at user logon; RunOnce entries are
// deleted after their first execution.
//
// HKLM keys require elevated privileges. HKCU keys persist only for the
// current user but do not require elevation.
package registry
