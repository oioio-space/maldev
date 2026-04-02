package testutil

// WindowsCanaryX64 is a minimal x64 stub: xor eax,eax; ret.
// Does nothing and returns cleanly. Verifies injection by thread completion.
var WindowsCanaryX64 = []byte{0x31, 0xC0, 0xC3}

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
