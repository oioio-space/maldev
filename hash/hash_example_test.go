package hash_test

import (
	"fmt"

	"github.com/oioio-space/maldev/hash"
)

// SHA-256 hex digest.
func ExampleSHA256() {
	fmt.Println(hash.SHA256([]byte("payload")))
	// Output: 239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5
}

// ROR13 — the canonical shellcode API hashing algorithm. Pre-computed
// constants in `win/api` use this for plaintext-free function
// resolution.
func ExampleROR13() {
	// Note: case-sensitive — must match the case used in your shellcode.
	fmt.Printf("%#x\n", hash.ROR13("LoadLibraryA"))
	// Output: 0xec0e4e8e
}

// ROR13Module hashes a name with a trailing null terminator — matches
// the convention used by PEB-walk shellcode that resolves module
// names from `LDR_DATA_TABLE_ENTRY.BaseDllName`.
func ExampleROR13Module() {
	fmt.Printf("%#x\n", hash.ROR13Module("kernel32.dll"))
}
