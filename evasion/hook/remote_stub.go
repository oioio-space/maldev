//go:build !windows

package hook

// RemoteOption configures RemoteInstall behaviour (no-op on this platform).
type RemoteOption func(*remoteConfig)

type remoteConfig struct{}

// WithMethod is a no-op on non-Windows platforms.
func WithMethod(_ interface{}) RemoteOption { return func(*remoteConfig) {} }

// RemoteInstall injects a hook handler into a remote process (unsupported on this platform).
func RemoteInstall(_ uint32, _, _ string, _ []byte, _ ...RemoteOption) error {
	return errUnsupported
}

// RemoteInstallByName resolves a process by name and injects a hook handler (unsupported on this platform).
func RemoteInstallByName(_, _, _ string, _ []byte, _ ...RemoteOption) error {
	return errUnsupported
}

// GoHandler converts a hook DLL to position-independent shellcode (unsupported on this platform).
func GoHandler(_, _ string) ([]byte, error) { return nil, errUnsupported }

// GoHandlerBytes converts raw DLL bytes to shellcode (unsupported on this platform).
func GoHandlerBytes(_ []byte, _ string) ([]byte, error) { return nil, errUnsupported }
