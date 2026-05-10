package testutil

// WindowsCanaryX64 is a minimal x64 stub: xor eax,eax; ret.
// Does nothing and returns cleanly. Verifies injection by thread completion.
var WindowsCanaryX64 = []byte{0x31, 0xC0, 0xC3}

// WindowsSearchableCanary is a longer canary for memory-scanning tests.
// Layout: xor eax,eax; ret followed by a unique 16-byte marker that is
// never executed (placed after ret). The marker "MALDEV_CANARY!!\n" is
// easy to find with a memory scan and won't collide with normal PE data.
var WindowsSearchableCanary = []byte{
	0x31, 0xC0, 0xC3, // xor eax,eax; ret
	'M', 'A', 'L', 'D', 'E', 'V', '_', 'C', 'A', 'N', 'A', 'R', 'Y', '!', '!', '\n',
}

// WindowsCETStubX64 is a CET-compliant no-op stub: endbr64; ret.
// Required on Windows 11+ where indirect jumps (KiUserApcDispatcher,
// thread-pool callbacks, etc.) are gated by the shadow stack and reject
// non-endbr64 targets with STATUS_STACK_BUFFER_OVERRUN (0xC000070A).
var WindowsCETStubX64 = []byte{0xF3, 0x0F, 0x1E, 0xFA, 0xC3}

// LinuxExit42ShellcodeX64 is 17 bytes of position-independent x86-64
// that issues the Linux exit_group syscall with status 42:
//
//	48 c7 c0 e7 00 00 00      mov rax, 231 (SYS_exit_group)
//	48 c7 c7 2a 00 00 00      mov rdi, 42
//	0f 05                     syscall
//
// Standard regression-contract fixture for end-to-end tests of the
// packer shellcode pipeline. Promoted to testutil so transform-,
// packer-, and CLI-layer tests stop redefining it independently.
var LinuxExit42ShellcodeX64 = []byte{
	0x48, 0xc7, 0xc0, 0xe7, 0x00, 0x00, 0x00, // mov rax, 231
	0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00, // mov rdi, 42
	0x0f, 0x05, // syscall
}

// LinuxExit42ShellcodeX64Compact is the smaller 12-byte
// x86-64 Linux variant using sys_exit (60) directly:
//
//	xor edi, edi    ; clear arg
//	mov dil, 42     ; arg = 42
//	mov eax, 60     ; sys_exit
//	syscall
//
// Picked over [LinuxExit42ShellcodeX64] (17 B sys_exit_group) when
// stub-size budget matters — sys_exit is per-thread but for a
// single-threaded test process the operational effect is the same.
var LinuxExit42ShellcodeX64Compact = []byte{
	0x31, 0xff, // xor edi, edi
	0x40, 0xb7, 0x2a, // mov dil, 42
	0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
	0x0f, 0x05, // syscall
}

// WindowsExit42ShellcodeX64 is 6 bytes of position-independent
// x86-64 that returns 42 to the caller:
//
//	b8 2a 00 00 00      mov eax, 42
//	c3                  ret
//
// Relies on ntdll!RtlUserThreadStart calling ExitProcess(rax) on
// the main thread when the entry-point function returns. Reliable
// on Win10 / 11 / Server 2019+ since the ABI hasn't changed.
//
// Standard regression-contract fixture for the Windows shellcode
// E2E gate.
var WindowsExit42ShellcodeX64 = []byte{
	0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax, 42
	0xc3, // ret
}

// LinuxCanaryX64 writes "MALDEV_OK\n" to stdout then exits with code 0.
//
//	lea rsi, [rip+msg]  ; 48 8d 35 15 00 00 00
//	mov rax, 1          ; 48 c7 c0 01 00 00 00  (sys_write)
//	mov rdi, 1          ; 48 c7 c7 01 00 00 00  (stdout)
//	mov rdx, 10         ; 48 c7 c2 0a 00 00 00  (length)
//	syscall             ; 0f 05
//	mov rax, 60         ; 48 c7 c0 3c 00 00 00  (sys_exit)
//	xor rdi, rdi        ; 48 31 ff              (code 0)
//	syscall             ; 0f 05
//	msg: "MALDEV_OK\n"
var LinuxCanaryX64 = []byte{
	0x48, 0x8d, 0x35, 0x15, 0x00, 0x00, 0x00,
	0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
	0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
	0x48, 0xc7, 0xc2, 0x0a, 0x00, 0x00, 0x00,
	0x0f, 0x05,
	0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,
	0x48, 0x31, 0xff,
	0x0f, 0x05,
	'M', 'A', 'L', 'D', 'E', 'V', '_', 'O', 'K', '\n',
}
