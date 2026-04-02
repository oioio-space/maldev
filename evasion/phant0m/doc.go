// Package phant0m provides Event Log service thread termination (Phant0m technique)
// to suppress Windows Event Log recording.
//
// Technique: Terminate threads of the Event Log service to prevent log writes.
// MITRE ATT&CK: T1562.002 (Impair Defenses: Disable Windows Event Logging)
// Platform: Windows
// Detection: High -- killing Event Log threads triggers alerts in mature environments.
//
// The Phant0m technique enumerates threads belonging to the Windows Event Log
// service (svchost.exe hosting EventLog) and terminates them individually,
// preventing new events from being written while the service appears running.
package phant0m
