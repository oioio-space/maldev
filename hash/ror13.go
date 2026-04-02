package hash

// ROR13 computes the ROR-13 hash of a Windows API function name.
// Uses the canonical shellcode algorithm: iterates raw bytes with no case folding.
func ROR13(name string) uint32 {
	var h uint32
	for i := 0; i < len(name); i++ {
		h = (h>>13 | h<<19) + uint32(name[i])
	}
	return h
}

// ROR13Module computes the ROR-13 hash of a module name with a null terminator,
// matching the shellcode convention for module name hashing.
func ROR13Module(name string) uint32 {
	return ROR13(name + "\x00")
}
