// Package meterpreter implements Metasploit Framework staging functionality
// for receiving and executing second-stage Meterpreter payloads.
//
// Technique: Meterpreter stager connecting to Metasploit multi/handler.
// MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
// Platform: Cross-platform (Windows and Linux)
// Detection: High -- Meterpreter staging is a well-known attack pattern;
// network signatures exist for all transport types.
//
// Supports three transport protocols:
//   - TCP: direct reverse TCP connection
//   - HTTP: reverse HTTP connection
//   - HTTPS: reverse HTTPS with optional InsecureSkipVerify
//
// Platform-specific execution:
//   - Windows: receives 4-byte size prefix + stage, executes via VirtualAlloc/CreateThread
//   - Linux: receives 126-byte wrapper shellcode that loads ELF from socket
package meterpreter
