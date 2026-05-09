package antivm

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

// TestBackdoorVMware_GatesOnPrivilege verifies that [BackdoorVMware]
// returns [ErrBackdoorPrivilege] when invoked from an unprivileged
// context — protecting the caller from a SIGSEGV at the IN instruction.
//
// On the CI / dev box (regular user) this is the expected path. The
// privileged path is exercised manually in a VM with `sudo go test`.
func TestBackdoorVMware_GatesOnPrivilege(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("VMware backdoor probe is amd64-only")
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		t.Skip("running as root: privilege gate skipped — covered by manual VM run")
	}

	rep, err := BackdoorVMware()
	if !errors.Is(err, ErrBackdoorPrivilege) {
		t.Errorf("BackdoorVMware err = %v, want ErrBackdoorPrivilege", err)
	}
	if rep.IsVMware {
		t.Error("IsVMware = true on declined probe")
	}
	if rep.PrivilegeOK {
		t.Error("PrivilegeOK = true on declined probe")
	}
	if rep.Echo != 0 || rep.ECX != 0 || rep.EDX != 0 {
		t.Errorf("Echo/ECX/EDX = %#x/%#x/%#x, want 0/0/0", rep.Echo, rep.ECX, rep.EDX)
	}
}

// TestBackdoorVMwareReport_FieldsZero is a defensive shape check on the
// zero value, useful when callers `var rep BackdoorVMwareReport` before
// passing through a chain of helpers.
func TestBackdoorVMwareReport_FieldsZero(t *testing.T) {
	var rep BackdoorVMwareReport
	if rep.IsVMware || rep.PrivilegeOK || rep.Echo != 0 || rep.ECX != 0 || rep.EDX != 0 {
		t.Errorf("zero value not all-zero: %+v", rep)
	}
}

// TestVMwareConstantsMatchSpec pins the protocol constants against the
// values published in VMware's open-vm-tools (lib/include/backdoor_def.h).
// A drift here would silently break the asm probe.
func TestVMwareConstantsMatchSpec(t *testing.T) {
	if vmwareMagic != 0x564D5868 {
		t.Errorf("vmwareMagic = %#x, want 0x564D5868 (\"VMXh\")", vmwareMagic)
	}
	if vmwarePort != 0x5658 {
		t.Errorf("vmwarePort = %#x, want 0x5658 (\"VX\")", vmwarePort)
	}
	if vmwareCmdGetVersion != 0x0A {
		t.Errorf("vmwareCmdGetVersion = %#x, want 0x0A", vmwareCmdGetVersion)
	}
	if vmwareSignature != vmwareMagic {
		t.Errorf("vmwareSignature = %#x, want %#x (must echo magic)", vmwareSignature, vmwareMagic)
	}
}
