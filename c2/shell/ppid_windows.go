//go:build windows

package shell

import (
	"fmt"

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
//
// TODO: Wire targetPID to cmd.SysProcAttr.ParentProcess via
// UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS).
// Currently FindTargetProcess discovers the PID but shell spawning
// does not apply it.
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
