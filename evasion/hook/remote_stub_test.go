//go:build !windows

package hook

import "testing"

func TestRemoteStubReturnsErrors(t *testing.T) {
	if err := RemoteInstall(1234, "ntdll.dll", "NtAllocateVirtualMemory", []byte{0x90}); err == nil {
		t.Error("RemoteInstall stub must return an error")
	}
	if err := RemoteInstallByName("notepad.exe", "ntdll.dll", "NtAllocateVirtualMemory", []byte{0x90}); err == nil {
		t.Error("RemoteInstallByName stub must return an error")
	}
	if _, err := GoHandler("./payload.dll", "Hook"); err == nil {
		t.Error("GoHandler stub must return an error")
	}
	if _, err := GoHandlerBytes([]byte{0x4d, 0x5a}, "Hook"); err == nil {
		t.Error("GoHandlerBytes stub must return an error")
	}
	// WithMethod is a no-op option; just exercise construction so lint sees it used.
	var cfg remoteConfig
	WithMethod(nil)(&cfg)
}
