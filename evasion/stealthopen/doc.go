// Package stealthopen opens files by their NTFS Object ID (a 128-bit GUID
// stored in the MFT) rather than by path, bypassing path-based EDR hooks on
// NtCreateFile / CreateFile.
//
// MITRE ATT&CK: T1036 — Masquerading
// Detection: Low (Object ID access not logged by most EDR path filters)
//
// Example:
//
//	oid, _ := stealthopen.GetObjectID(`C:\payload.bin`)
//	f, _ := stealthopen.OpenByID(`C:\`, oid)
//	defer f.Close()
package stealthopen
