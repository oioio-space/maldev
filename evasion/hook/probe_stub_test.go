//go:build !windows

package hook

import "testing"

func TestProbeStubReturnsErrors(t *testing.T) {
	if _, err := InstallProbe(0x1000, func(ProbeResult) {}); err == nil {
		t.Error("InstallProbe stub must return an error")
	}
	if _, err := InstallProbeByName("ntdll.dll", "NtAllocateVirtualMemory", func(ProbeResult) {}); err == nil {
		t.Error("InstallProbeByName stub must return an error")
	}
	var r ProbeResult
	if got := r.NonZeroArgs(); got != nil {
		t.Errorf("NonZeroArgs stub = %v, want nil", got)
	}
	if got := r.NonZeroCount(); got != 0 {
		t.Errorf("NonZeroCount stub = %d, want 0", got)
	}
}
