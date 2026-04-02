# Syscall Methods

[<- Back to README](../README.md)

The `win/syscall` package provides a `Caller` that routes NT function calls through four strategies, allowing the same injection or evasion code to transparently switch between detectable WinAPI calls and stealthy indirect syscalls.

## Method Comparison

| Method | Constant | Bypass kernel32 hooks | Bypass ntdll hooks | Survive memory scan | Survive stack analysis |
|--------|----------|----------------------|-------------------|--------------------|-----------------------|
| WinAPI | `MethodWinAPI` | No | No | -- | -- |
| NativeAPI | `MethodNativeAPI` | Yes | No | -- | -- |
| Direct | `MethodDirect` | Yes | Yes | No | -- |
| Indirect | `MethodIndirect` | Yes | Yes | Yes | Yes |

## SSN Resolvers

SSN Resolvers determine the Syscall Service Number for each NT function:

| Resolver | Function | Handles hooked functions |
|----------|----------|------------------------|
| `NewHellsGate()` | Reads SSN from ntdll prologue | No -- fails if hooked |
| `NewHalosGate()` | Scans neighboring stubs | Yes -- sequential SSN arithmetic |
| `NewTartarus()` | Extends Halo's Gate | Yes -- JMP hook displacement |
| `Chain(r1, r2, ...)` | Tries resolvers in sequence | Yes -- first success wins |

## Example: Switching Syscall Methods

```go
import wsyscall "github.com/oioio-space/maldev/win/syscall"

// Standard WinAPI (default, most compatible)
caller := wsyscall.New(wsyscall.MethodWinAPI, nil)

// Direct syscall with Hell's Gate SSN resolution
caller = wsyscall.New(wsyscall.MethodDirect, wsyscall.NewHellsGate())

// Indirect syscall with chained resolvers (most stealthy)
caller = wsyscall.New(
    wsyscall.MethodIndirect,
    wsyscall.Chain(wsyscall.NewHellsGate(), wsyscall.NewHalosGate()),
)

// Pass the caller to any technique that accepts *wsyscall.Caller
err := amsi.PatchScanBuffer(caller)
err = etw.Patch(caller)
err = blockdlls.Enable(caller)
err = acg.Enable(caller)
```

All technique packages that accept a `*wsyscall.Caller` parameter treat `nil` as "use standard WinAPI", making the syscall method entirely opt-in.
