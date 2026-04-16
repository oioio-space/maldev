//go:build go1.21

package memclear

// Clear zeros the byte slice using the go1.21 clear builtin.
// The compiler treats clear as an intrinsic and will not eliminate it as a
// dead store, making it safe for wiping sensitive material.
func Clear(buf []byte) {
	clear(buf)
}
