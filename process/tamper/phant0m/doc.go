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
//
// How it works: The Windows Event Log service runs as a set of threads inside
// a shared svchost.exe process. Rather than stopping the service (which would
// trigger an alert), Phant0m identifies the specific svchost process hosting
// the EventLog service, enumerates its threads, and terminates each one
// individually using TerminateThread. The service remains registered as
// "running" in the SCM, but with no threads alive, no new log entries can be
// written -- effectively silencing the event log without a visible service stop.
package phant0m
