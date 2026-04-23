//go:build !go1.26 || !goexperiment.runtimesecret

package memory

// DoSecret invokes f. This is the portable stub used whenever the build is
// not Go 1.26+ with GOEXPERIMENT=runtimesecret. It provides the same calling
// shape as the runtime/secret-backed variant (see secret_experimental.go) so
// callers can unconditionally wrap sensitive computations and opt into
// register/stack/heap erasure simply by rebuilding with the experiment on.
//
// No erasure is performed by this stub. Pair it with SecureZero for any
// byte-slice material that must be wiped unconditionally.
func DoSecret(f func()) {
	f()
}

// SecretEnabled reports whether runtime/secret erasure is active for the
// current goroutine. Always false in the stub build.
func SecretEnabled() bool {
	return false
}
