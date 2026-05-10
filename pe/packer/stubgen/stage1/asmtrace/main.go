//go:build windows && amd64

// Package main implements a Windows-only diagnostic harness for
// hand-encoded asm primitives.
//
// Operational shape: read raw asm bytes from a file, allocate an
// RWX page, register a Vectored Exception Handler that dumps
// CONTEXT_RECORD + EXCEPTION_RECORD on crash, jump into the asm.
//
//   - asm calls ExitProcess(N): harness never returns; process exits with N.
//   - asm faults: VEH dumps a structured trace to stderr in the form
//
//     ASMTRACE: exception=0xc0000005 at 0x140001234
//     RIP = 0x140001234
//     RAX = 0x... RBX = 0x... RCX = 0x... RDX = 0x...
//     RSI = 0x... RDI = 0x... RSP = 0x... RBP = 0x...
//     R8  = 0x... R9  = 0x... R10 = 0x... R11 = 0x...
//     R12 = 0x... R13 = 0x... R14 = 0x... R15 = 0x...
//     faulting addr = 0x... op = 0|1|8 (read/write/dep-violation)
//
//     then returns EXCEPTION_CONTINUE_SEARCH so the OS terminates the
//     process with the original exception code (visible to the caller
//     as the high-bit-set exit code).
//   - asm rets without calling ExitProcess: harness writes a sentinel
//     line and exits with code 98.
//
// Used by [pe/packer/stubgen/stage1] runtime tests via go-build +
// exec — converts opaque ACCESS_VIOLATION into actionable register
// trace pinpointing the faulting instruction.
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// contextX64 mirrors the relevant prefix of the Windows AMD64
// CONTEXT structure. Offsets validated against the Microsoft Win32
// API documentation:
//
//	0x00 P1Home..P6Home  (6 × DWORD64 = 48 B)
//	0x30 ContextFlags    (DWORD)
//	0x34 MxCsr           (DWORD)
//	0x38 SegCs..SegSs    (6 × WORD = 12 B)
//	0x44 EFlags          (DWORD)
//	0x48 Dr0..Dr3, Dr6, Dr7 (6 × DWORD64 = 48 B)
//	0x78 Rax..Rdi        (8 × DWORD64 = 64 B)
//	0xb8 R8..R15         (8 × DWORD64 = 64 B)
//	0xf8 Rip             (DWORD64)
//	(xmm regs etc. follow but we don't read them)
type contextX64 struct {
	P1Home, P2Home, P3Home, P4Home, P5Home, P6Home uint64
	ContextFlags                                   uint32
	MxCsr                                          uint32
	SegCs, SegDs, SegEs, SegFs, SegGs, SegSs       uint16
	EFlags                                         uint32
	Dr0, Dr1, Dr2, Dr3, Dr6, Dr7                   uint64
	Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi         uint64
	R8, R9, R10, R11, R12, R13, R14, R15           uint64
	Rip                                            uint64
}

// exceptionRecord mirrors EXCEPTION_RECORD (sufficient prefix).
type exceptionRecord struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecordPtr   uintptr
	ExceptionAddress     uintptr
	NumberParameters     uint32
	_                    uint32
	ExceptionInformation [15]uintptr
}

// exceptionPointers mirrors EXCEPTION_POINTERS.
type exceptionPointers struct {
	ExceptionRecord *exceptionRecord
	ContextRecord   *contextX64
}

func vehHandler(info uintptr) uintptr {
	ptrs := (*exceptionPointers)(unsafe.Pointer(info))
	rec := ptrs.ExceptionRecord
	ctx := ptrs.ContextRecord

	// fmt.Fprintf is goroutine-safe and the OS thread is owned by the
	// Go runtime — calling it from inside VEH works in practice for
	// our purposes (small allocation, no GC scan of asm stack frames
	// because the asm doesn't use Go-managed memory).
	fmt.Fprintf(os.Stderr, "ASMTRACE: exception=%#x at %#x\n",
		rec.ExceptionCode, rec.ExceptionAddress)
	fmt.Fprintf(os.Stderr, "  RIP = %#016x\n", ctx.Rip)
	fmt.Fprintf(os.Stderr, "  RAX = %#016x  RBX = %#016x  RCX = %#016x  RDX = %#016x\n",
		ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx)
	fmt.Fprintf(os.Stderr, "  RSI = %#016x  RDI = %#016x  RSP = %#016x  RBP = %#016x\n",
		ctx.Rsi, ctx.Rdi, ctx.Rsp, ctx.Rbp)
	fmt.Fprintf(os.Stderr, "  R8  = %#016x  R9  = %#016x  R10 = %#016x  R11 = %#016x\n",
		ctx.R8, ctx.R9, ctx.R10, ctx.R11)
	fmt.Fprintf(os.Stderr, "  R12 = %#016x  R13 = %#016x  R14 = %#016x  R15 = %#016x\n",
		ctx.R12, ctx.R13, ctx.R14, ctx.R15)
	if rec.NumberParameters >= 2 {
		// ExceptionInformation[0]: 0=read, 1=write, 8=DEP
		// ExceptionInformation[1]: faulting virtual address
		fmt.Fprintf(os.Stderr, "  faulting addr = %#016x  op = %d (0=read 1=write 8=DEP)\n",
			rec.ExceptionInformation[1], rec.ExceptionInformation[0])
	}
	// EXCEPTION_CONTINUE_SEARCH — let the OS continue unwinding and
	// terminate the process naturally with the original exception code.
	return 0
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: asmtrace <asm.bin>")
		os.Exit(2)
	}
	asm, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ASMTRACE: read %s: %v\n", os.Args[1], err)
		os.Exit(2)
	}

	// Register VEH (kernel32!AddVectoredExceptionHandler).
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	addVEH := kernel32.NewProc("AddVectoredExceptionHandler")
	cb := syscall.NewCallback(vehHandler)
	if r1, _, e := addVEH.Call(1, cb); r1 == 0 {
		fmt.Fprintf(os.Stderr, "ASMTRACE: AddVectoredExceptionHandler: %v\n", e)
		os.Exit(2)
	}

	// VirtualAlloc RWX page.
	ptr, err := windows.VirtualAlloc(
		0,
		uintptr(len(asm)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ASMTRACE: VirtualAlloc: %v\n", err)
		os.Exit(2)
	}
	page := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(asm))
	copy(page, asm)

	// Jump into asm. SyscallN works for arbitrary addresses on
	// Windows; the asm controls the entire flow from there.
	_, _, _ = syscall.SyscallN(ptr)

	// Unreachable if asm calls ExitProcess; falls through if asm
	// returns without calling ExitProcess (a different bug — caller
	// asm forgot to terminate the process).
	fmt.Fprintln(os.Stderr, "ASMTRACE: asm returned without calling ExitProcess (bug — primitive must terminate)")
	os.Exit(98)
}
