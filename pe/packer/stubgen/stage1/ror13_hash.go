package stage1

// ROR-13 hashing — the canonical shellcode primitive for resolving
// Windows API exports without an IAT entry.
//
// Two variants are used by [EmitResolveKernel32Export]:
//   - [Ror13HashUnicodeUpper] hashes a module name as it appears in
//     LDR_DATA_TABLE_ENTRY.BaseDllName (UTF-16LE, case-insensitive —
//     the asm folds lowercase letters to uppercase before the XOR).
//   - [Ror13HashASCII] hashes an export name as it appears in the
//     PE export-name table (NUL-terminated ASCII, case-sensitive —
//     Windows exports are case-sensitive).
//
// Both seeds at 0 and consume each character through:
//
//	hash = ROR32(hash, 13) XOR uint32(char)
//
// The 13-bit rotation is folklore (Stephen Fewer's reflective-DLL-
// injection code popularised it in 2008); any odd rotation gives
// similar distribution. We pin 13 because the constant is what every
// reference PEB-walker has emitted for fifteen years — operators
// running yara on shellcode often pin on this byte pattern.

// ror32 rotates v right by k bits within 32 bits.
func ror32(v uint32, k uint) uint32 {
	k &= 31
	return (v >> k) | (v << (32 - k))
}

// Ror13HashASCII hashes a NUL-terminated ASCII string with the
// ROR-13 + XOR shellcode hash. Case-sensitive (matches Windows
// export-name semantics).
func Ror13HashASCII(s string) uint32 {
	var h uint32
	for i := 0; i < len(s); i++ {
		h = ror32(h, 13) ^ uint32(s[i])
	}
	return h
}

// Ror13HashUnicodeUpper hashes a string as if it were UTF-16LE +
// folded to uppercase before each XOR. Matches the asm loop that
// walks LDR_DATA_TABLE_ENTRY.BaseDllName.
//
// Folding rule: ASCII [a-z] maps to its uppercase counterpart by
// subtracting 0x20. All other code points are passed through as-is.
// Mirrors the asm's `cmp eax, 0x60 / jbe / cmp eax, 0x7a / ja /
// sub eax, 0x20` sequence.
func Ror13HashUnicodeUpper(s string) uint32 {
	var h uint32
	for _, r := range s {
		c := uint32(r)
		if c >= 'a' && c <= 'z' {
			c -= 0x20
		}
		h = ror32(h, 13) ^ c
	}
	return h
}

// Kernel32DLLHash is the [Ror13HashUnicodeUpper] of "kernel32.dll" —
// pinned at init so [EmitResolveKernel32Export] can splice it into
// the asm template without re-hashing per call. The matching asm
// folds case so any Windows BaseDllName variant ("KERNEL32.DLL" /
// "kernel32.dll") yields the same hash.
var Kernel32DLLHash = Ror13HashUnicodeUpper("kernel32.dll")
