// Package multicat provides a multi-session reverse shell listener for operator use.
//
// It accepts incoming connections from reverse-shell agents (c2/shell), assigns each
// a sequential session ID, and emits events over a channel. Sessions are held in memory;
// they do not survive a manager restart.
//
// Wire protocol (BANNER): when an agent connects, multicat reads the first line with a
// 500 ms deadline. If the line has the form "BANNER:<hostname>\n", the hostname is stored
// in SessionMetadata. All other bytes are part of the normal shell I/O stream.
//
// Technique: Multi-handler / session multiplexing (operator-side only)
// MITRE ATT&CK: T1571 — Non-Standard Port
// Platform: Cross-platform
// Detection: Low — package is never embedded in the implant.
//
// Example:
//
//	l, _ := transport.NewTCPListener(":4444")
//	mgr := multicat.New()
//	go mgr.Listen(ctx, l)
//
//	for ev := range mgr.Events() {
//	    if ev.Type == multicat.EventOpened {
//	        fmt.Printf("[+] %s from %s\n", ev.Session.Meta.ID, ev.Session.Meta.RemoteAddr)
//	    }
//	}
package multicat
