package shellcode

import "encoding/binary"

// Block returns a shellcode that returns 0 (FALSE), blocking the API call.
// 3 bytes: xor eax, eax; ret
func Block() []byte {
	return []byte{0x31, 0xC0, 0xC3}
}

// Nop returns a shellcode that JMPs to trampolineAddr (calls original function unchanged).
// 13 bytes: mov r10, imm64; jmp r10
func Nop(trampolineAddr uintptr) []byte {
	stub := []byte{0x49, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0, 0x41, 0xFF, 0xE2}
	binary.LittleEndian.PutUint64(stub[2:], uint64(trampolineAddr))
	return stub
}

// Replace returns a shellcode that returns a fixed value.
// 11 bytes: mov rax, imm64; ret
func Replace(returnValue uintptr) []byte {
	stub := []byte{0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3}
	binary.LittleEndian.PutUint64(stub[2:], uint64(returnValue))
	return stub
}

// Redirect returns a shellcode that JMPs to targetAddr.
// 13 bytes: mov r10, imm64; jmp r10
func Redirect(targetAddr uintptr) []byte {
	stub := []byte{0x49, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0, 0x41, 0xFF, 0xE2}
	binary.LittleEndian.PutUint64(stub[2:], uint64(targetAddr))
	return stub
}
