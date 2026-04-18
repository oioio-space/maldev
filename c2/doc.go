// Package c2 provides command and control building blocks: reverse shells,
// Meterpreter staging, pluggable transports (TCP/TLS/uTLS/NamedPipe), mTLS
// certificate helpers, and session multiplexing.
//
// Technique: Operator-side C2 primitives. Not an attack technique per se --
// this is the communication + session layer atop which implants compose
// injection, evasion, and collection features.
// MITRE ATT&CK: T1071 (Application Layer Protocol), T1573 (Encrypted
// Channel), T1095 (Non-Application Layer Protocol), T1059 (Command and
// Scripting Interpreter, via c2/shell).
// Platform: Cross-platform core; windows-only extras (named pipe, PPID
// spoofing for spawned shells).
// Detection: Varies -- TLS with ja3/ja4 fingerprint randomization is Low;
// plain TCP is High.
//
// Sub-packages:
//
//   - c2/transport:          pluggable TCP/TLS/uTLS transports + Factory
//   - c2/transport/namedpipe: Windows named pipe transport (lateral movement)
//   - c2/cert:               operator mTLS cert generation with pinning
//   - c2/shell:              reverse shell with PTY + auto-reconnect
//   - c2/meterpreter:        Metasploit Meterpreter stager
//   - c2/multicat:           multi-session listener with BANNER wire protocol
//
// Import the specific sub-package for your use case.
package c2
