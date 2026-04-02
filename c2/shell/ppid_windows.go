//go:build windows

package shell

import (
	"fmt"

	"github.com/oioio-space/maldev/process/enum"
)

// PPIDSpoofing provides PPID spoofing capabilities.
//
// TODO: Wire targetPID to cmd.SysProcAttr.ParentProcess via
// UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS).
// Currently FindTargetProcess discovers the PID but shell spawning
// does not apply it.
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
		procs, err := enum.FindByName(target)
		if err == nil && len(procs) > 0 {
			p.targetPID = procs[0].PID
			return nil
		}
	}

	return fmt.Errorf("no suitable parent process found")
}

// TargetPID returns the selected target process ID.
func (p *PPIDSpoofing) TargetPID() uint32 {
	return p.targetPID
}

// GetParentProcessID returns the parent process ID of the given PID.
func GetParentProcessID(pid uint32) (uint32, error) {
	proc, err := enum.FindProcess(func(_ string, p, _ uint32) bool {
		return p == pid
	})
	if err != nil {
		return 0, fmt.Errorf("process %d not found", pid)
	}
	return proc.PPID, nil
}
