package hash

import "strings"

// ROR13 computes the ROR-13 hash of a Windows API function name.
// Used in shellcode to resolve API addresses without plaintext strings.
func ROR13(name string) uint32 {
	var h uint32
	for _, c := range strings.ToUpper(name) {
		h = (h>>13 | h<<19) + uint32(c)
	}
	return h
}

func ROR13Module(name string) uint32 { return ROR13(name) }
