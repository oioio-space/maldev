// Package service provides Windows service persistence via the Service Control Manager.
//
// Technique: Windows service persistence via Service Control Manager.
// MITRE ATT&CK: T1543.003 (Create or Modify System Process: Windows Service)
// Platform: Windows
// Detection: High -- service creation generates System event 7045 and Security
// event 4697; services are visible in services.msc and via sc query.
//
// How it works: Creates a Windows service entry in the SCM database that
// starts the specified executable automatically at boot. Requires
// administrator privileges for installation.
package service
