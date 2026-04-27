package memory_test

import (
	"fmt"

	"github.com/oioio-space/maldev/cleanup/memory"
)

// SecureZero overwrites a slice with zeros via Go's `clear` builtin so
// the compiler cannot elide the writes as dead stores.
func ExampleSecureZero() {
	key := []byte("very-secret-key-material!")
	defer memory.SecureZero(key)
	// use key here…
	fmt.Println(len(key))
	// Output: 25
}

// DoSecret runs the supplied function inside a runtime-secret scope.
// With Go 1.26+ and GOEXPERIMENT=runtimesecret, scratch
// registers/stack/heap used during f are erased on return. Without that
// toolchain DoSecret is a plain call — safe to wrap unconditionally.
func ExampleDoSecret() {
	var derived []byte
	memory.DoSecret(func() {
		// imagine pbkdf2(password, salt, …)
		tmp := []byte("derived-key-bytes-here-32B")
		derived = make([]byte, len(tmp))
		copy(derived, tmp)
	})
	fmt.Println(len(derived))
	// Output: 26
}
