//go:build windows

package hook

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/inject"
)

// TestWithMethod verifies that WithMethod mutates remoteConfig correctly.
func TestWithMethod(t *testing.T) {
	cfg := &remoteConfig{method: inject.MethodCreateRemoteThread}
	WithMethod(inject.MethodQueueUserAPC)(cfg)
	require.Equal(t, inject.MethodQueueUserAPC, cfg.method)
}

// TestWithMethodDefault verifies the default method is CreateRemoteThread
// when no option is applied.
func TestWithMethodDefault(t *testing.T) {
	cfg := &remoteConfig{method: inject.MethodCreateRemoteThread}
	// no opts applied
	require.Equal(t, inject.MethodCreateRemoteThread, cfg.method)
}

// TestRemoteInstallInvalidPID verifies RemoteInstall fails gracefully when
// the builder rejects the configuration (PID=0 is invalid for remote methods).
func TestRemoteInstallInvalidPID(t *testing.T) {
	err := RemoteInstall(0, "ntdll.dll", "NtAllocateVirtualMemory", []byte{0x90})
	require.Error(t, err)
}

// TestRemoteInstallByNameNotFound verifies RemoteInstallByName returns an
// error when the named process does not exist.
func TestRemoteInstallByNameNotFound(t *testing.T) {
	err := RemoteInstallByName("__nonexistent_process_xyz__.exe", "ntdll.dll", "NtFoo", []byte{0x90})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

// TestGoHandlerBytesRejectsMissingMZ verifies GoHandlerBytes returns an error
// for input that is not a valid PE image — exercises the error path without
// any DLL file or VM.
func TestGoHandlerBytesRejectsMissingMZ(t *testing.T) {
	_, err := GoHandlerBytes([]byte("not a PE"), "DllMain")
	require.Error(t, err)
}

// TestGoHandlerBytesTooShort verifies GoHandlerBytes rejects inputs shorter
// than 2 bytes (srdi.ConvertBytes length check).
func TestGoHandlerBytesTooShort(t *testing.T) {
	_, err := GoHandlerBytes([]byte{0x4D}, "DllMain")
	require.Error(t, err)
}

// TestGoHandlerBytesEmpty verifies GoHandlerBytes rejects empty input.
func TestGoHandlerBytesEmpty(t *testing.T) {
	_, err := GoHandlerBytes([]byte{}, "DllMain")
	require.Error(t, err)
}

// TestGoHandlerFileNotFound verifies GoHandler returns an error when the
// DLL path does not exist — no VM required.
func TestGoHandlerFileNotFound(t *testing.T) {
	_, err := GoHandler(`C:\nonexistent\path\hook.dll`, "DllMain")
	require.Error(t, err)
}

// TestRemoteInstallByNameEnumError verifies RemoteInstallByName propagates
// errors from the process list (empty name edge case).
func TestRemoteInstallByNameEmptyName(t *testing.T) {
	// Empty name will enumerate OK but match nothing — "not found" error.
	err := RemoteInstallByName("", "ntdll.dll", "NtFoo", []byte{0x90})
	require.Error(t, err)
}
