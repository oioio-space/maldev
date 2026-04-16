// Package namedpipe provides a Windows named pipe transport implementing
// the transport.Transport and transport.Listener interfaces.
//
// Technique: Named pipe IPC for local and SMB-based C2 communication.
// MITRE ATT&CK: T1071.001 (Application Layer Protocol)
// Platform: Windows
// Detection: Medium
//
// Named pipes are a natural IPC mechanism on Windows, used extensively by
// legitimate services (SMB, RPC, print spooler). This makes pipe-based C2
// traffic blend with normal OS activity on the local host or across an SMB
// peer network.
//
// Server side:
//
//	ln, err := namedpipe.NewListener(`\\.\pipe\myc2`)
//	conn, err := ln.Accept(ctx)
//
// Client side:
//
//	p := namedpipe.New(`\\.\pipe\myc2`, 5*time.Second)
//	err := p.Connect(ctx)
//	p.Write([]byte("hello"))
package namedpipe
