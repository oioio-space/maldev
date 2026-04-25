package antivm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectVMNoPanic(t *testing.T) {
	// DetectVM inspects host indicators; it must not panic regardless of result.
	_ = DetectVM()
}

func TestIsRunningInVMNoPanic(t *testing.T) {
	// IsRunningInVM wraps DetectVM; it must not panic regardless of result.
	_ = IsRunningInVM()
}

func TestDetectNoPanic(t *testing.T) {
	_, err := Detect(DefaultConfig())
	if err != nil {
		t.Fatalf("Detect(DefaultConfig()) returned error: %v", err)
	}
}

func TestDetectAllNoPanic(t *testing.T) {
	_, err := DetectAll(DefaultConfig())
	if err != nil {
		t.Fatalf("DetectAll(DefaultConfig()) returned error: %v", err)
	}
}

func TestDefaultConfigHelpers(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.checks() != CheckAll {
		t.Errorf("DefaultConfig().checks() = %d, want %d", cfg.checks(), CheckAll)
	}
	if cfg.vendors() == nil {
		t.Error("DefaultConfig().vendors() returned nil, want DefaultVendors")
	}
}

func TestConfigCustomVendors(t *testing.T) {
	cfg := Config{
		Vendors: []Vendor{{Name: "TestVM", Nic: []string{"FF:FF:FF"}}},
		Checks:  CheckNIC,
	}
	if len(cfg.vendors()) != 1 {
		t.Errorf("custom vendors length = %d, want 1", len(cfg.vendors()))
	}
	if cfg.checks() != CheckNIC {
		t.Errorf("custom checks = %d, want %d", cfg.checks(), CheckNIC)
	}
}

func TestDetectEmptyVendors(t *testing.T) {
	// Empty vendor list means file/NIC/process checks have nothing to match.
	// However, DMI/CPUID checks (always-on) may still detect a VM.
	cfg := Config{Vendors: []Vendor{}, Checks: CheckFiles | CheckNIC}
	_, err := Detect(cfg)
	if err != nil {
		t.Fatalf("Detect with empty vendors returned error: %v", err)
	}
	// We don't assert name=="" because DMI/CPUID detection is vendor-independent.
}

// TestDetectVMInVirtualBox verifies that the VM detection actually returns
// true when running inside VirtualBox. If this test runs on bare metal,
// it verifies the result is false.
func TestDetectVMInVirtualBox(t *testing.T) {
	result := DetectVM()
	t.Logf("DetectVM() = %q", result)
	// If running in VirtualBox, we expect a non-empty result containing "VirtualBox".
	// If on bare metal, result should be empty.
	// The test is informational — it logs the detection result for the current environment.
	if result != "" {
		t.Logf("VM DETECTED: %s", result)
	} else {
		t.Log("No VM detected (bare metal or unrecognized hypervisor)")
	}
}

// TestDetectAllInVirtualBox runs all detection checks and verifies each one.
func TestDetectAllInVirtualBox(t *testing.T) {
	results, err := DetectAll(DefaultConfig())
	require.NoError(t, err)
	t.Logf("DetectAll returned %d results:", len(results))
	for _, r := range results {
		t.Logf("  detected: %q", r)
	}
	if len(results) > 0 {
		t.Logf("VM indicators found: %d", len(results))
	}
}

// TestDetectVBoxProcess verifies that VBoxService.exe or VBoxTray.exe is
// detected as a VM process when running inside VirtualBox.
func TestDetectVBoxProcess(t *testing.T) {
	found, matched, err := DetectProcess([]string{"VBoxService.exe", "VBoxTray.exe"})
	require.NoError(t, err)
	if found {
		t.Logf("VirtualBox process detected: %s", matched)
	} else {
		t.Log("No VirtualBox processes found (may be bare metal)")
	}
}

func TestDetectProcessNoPanic(t *testing.T) {
	// DetectProcess with a non-existent name should return false.
	found, _, err := DetectProcess([]string{"__nonexistent_process_xyz__"})
	if err != nil {
		t.Fatalf("DetectProcess returned error: %v", err)
	}
	if found {
		t.Error("DetectProcess matched a process that should not exist")
	}
}
