package memory

import (
	"github.com/oioio-space/maldev/internal/compat/memclear"
)

// SecureZero overwrites a byte slice with zeros in a way that the compiler
// cannot optimize away. On Go 1.21+, delegates to the clear builtin intrinsic.
func SecureZero(buf []byte) {
	memclear.Clear(buf)
}
