package antivm

import (
	"testing"
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
