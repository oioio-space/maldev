//go:build go1.26 && goexperiment.runtimesecret

package memory

import "runtime/secret"

// DoSecret invokes f while ensuring that registers, stack slots, and heap
// allocations used by f are erased after it returns (including on panic or
// runtime.Goexit). Backed by the Go 1.26 runtime/secret package. Effective
// erasure is implemented only on linux/amd64 and linux/arm64; on other
// platforms runtime/secret.Do still runs f but performs no wipe.
//
// Build this variant with Go 1.26+ and GOEXPERIMENT=runtimesecret. Without
// that experiment, the stub in secret_stub.go is selected.
//
// Construct outputs outside DoSecret and copy into them from inside; values
// that escape the closure are not erased.
func DoSecret(f func()) {
	secret.Do(f)
}

// SecretEnabled reports whether a DoSecret call is on the current goroutine's
// stack (i.e. secret-erasure semantics are in effect for the caller).
func SecretEnabled() bool {
	return secret.Enabled()
}
