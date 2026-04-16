// Package bridge provides a bidirectional control channel between a hook
// handler running in a target process and the implant that injected it.
//
// Technique: Named pipe or TCP-based IPC for real-time hook control.
// MITRE ATT&CK: T1574.012 — Hijack Execution Flow: Inline Hooking.
// Platform: Windows.
// Detection: Medium — named pipe / TCP connections are visible.
//
// Two modes:
//
//	ctrl := bridge.Standalone()               // autonomous, no communication
//	ctrl, _ := bridge.Connect(transport)      // implant-controlled
package bridge
