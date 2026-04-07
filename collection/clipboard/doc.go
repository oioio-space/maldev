// Package clipboard provides Windows clipboard monitoring and capture.
//
// Technique: Windows clipboard monitoring and capture.
// MITRE ATT&CK: T1115 (Clipboard Data)
// Platform: Windows
// Detection: Medium -- clipboard access via OpenClipboard is observable but common.
//
// ReadText extracts the current clipboard text in a single call.
// Watch polls the clipboard sequence number and streams text changes
// through a channel until the context is cancelled.
package clipboard
