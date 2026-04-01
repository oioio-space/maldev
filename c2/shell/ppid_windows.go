//go:build windows

package shell

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PPIDSpoofing provides PPID spoofing capabilities.
type PPIDSpoofing struct {
	targetPID uint32
}

// NewPPIDSpoofing creates a new PPIDSpoofing instance.
func NewPPIDSpoofing() *PPIDSpoofing {
	return &PPIDSpoofing{}
}

// FindTargetProcess finds a suitable legitimate parent process.
func (p *PPIDSpoofing) FindTargetProcess() error {
	targets := []string{
		"explorer.exe",
		"svchost.exe",
		"sihost.exe",
		"RuntimeBroker.exe",
	}

	for _, target := range targets {
		pid, err := findProcessByName(target)
		if err == nil && pid != 0 {
			p.targetPID = pid
			return nil
		}
	}

	return fmt.Errorf("no suitable parent process found")
}

// TargetPID returns the selected target process ID.
func (p *PPIDSpoofing) TargetPID() uint32 {
	return p.targetPID
}

// findProcessByName finds a process by its executable name.
func findProcessByName(name string) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	err = windows.Process32First(snapshot, &procEntry)
	if err != nil {
		return 0, fmt.Errorf("Process32First: %w", err)
	}

	for {
		exeFile := windows.UTF16ToString(procEntry.ExeFile[:])
		if exeFile == name {
			return procEntry.ProcessID, nil
		}

		err = windows.Process32Next(snapshot, &procEntry)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("process %s not found", name)
}

// GetParentProcessID returns the parent process ID of the given PID.
func GetParentProcessID(pid uint32) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	if err := windows.Process32First(snapshot, &procEntry); err != nil {
		return 0, err
	}

	for {
		if procEntry.ProcessID == pid {
			return procEntry.ParentProcessID, nil
		}

		if err := windows.Process32Next(snapshot, &procEntry); err != nil {
			break
		}
	}

	return 0, fmt.Errorf("process %d not found", pid)
}
