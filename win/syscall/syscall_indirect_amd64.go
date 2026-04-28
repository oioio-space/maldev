//go:build windows && amd64

package syscall

// indirectSyscallAsm is implemented in syscall_indirect_amd64.s.
//
// Calling convention (Win64 NT, the kernel ABI):
//
//   - ssn        — system service number, loaded into EAX
//   - trampoline — address of a `syscall;ret` gadget inside ntdll.dll
//   - args       — up to 16 NT syscall arguments (first 4 in registers, rest
//     spilled to the stack frame the stub allocates)
//
// Returns the raw NTSTATUS as uint32. Callers treat any non-zero value as
// failure (matches the convention used by the other Caller methods).
//
//go:noescape
func indirectSyscallAsm(ssn uint16, trampoline uintptr, args ...uintptr) uint32
