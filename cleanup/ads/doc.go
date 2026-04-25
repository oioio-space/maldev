// Package ads provides CRUD operations for NTFS Alternate Data Streams.
//
// Alternate Data Streams (ADS) are hidden data storage areas within NTFS files.
// Each file can have multiple named streams beyond the default :$DATA stream.
// ADS are commonly used for:
//   - Data hiding (T1564.004)
//   - Persistence (store payloads in ADS of legitimate files)
//   - Self-deletion (rename default stream before delete)
//
// Example:
//
//	// Write payload to ADS
//	err := ads.Write(`C:\Users\Public\desktop.ini`, "payload", shellcode)
//
//	// List all streams
//	streams, err := ads.List(`C:\Users\Public\desktop.ini`)
//
//	// Read it back
//	data, err := ads.Read(`C:\Users\Public\desktop.ini`, "payload")
//
//	// Delete the stream
//	err = ads.Delete(`C:\Users\Public\desktop.ini`, "payload")
//
// Technique: NTFS Alternate Data Streams
// MITRE ATT&CK: T1564.004 (Hide Artifacts: NTFS File Attributes)
// Platform: Windows only (NTFS filesystem required)
// Detection: Medium — Sysinternals Streams, PowerShell Get-Item -Stream *,
// and some EDR products can enumerate ADS.
//
// References:
//   - https://github.com/microsoft/go-winio/blob/main/backup.go
//   - https://cqureacademy.com/blog/alternate-data-streams/
package ads
