package antivm

// CheckType is a bitmask selecting which detection dimensions to evaluate.
//
// Use bitwise OR to combine checks:
//
//	// Only check registry keys and files:
//	cfg := antivm.Config{Checks: antivm.CheckRegistry | antivm.CheckFiles}
//
//	// Check everything (default when Checks is 0):
//	cfg := antivm.DefaultConfig()
type CheckType uint

const (
	// CheckRegistry enables registry-key detection (Windows only, skipped on Linux).
	CheckRegistry CheckType = 1 << iota
	// CheckFiles enables filesystem artifact detection.
	CheckFiles
	// CheckNIC enables MAC address prefix detection.
	CheckNIC
	// CheckProcess enables running-process detection.
	CheckProcess
	// CheckCPUID enables hypervisor CPUID / product-name detection.
	CheckCPUID
	// CheckAll enables every detection dimension.
	CheckAll = CheckRegistry | CheckFiles | CheckNIC | CheckProcess | CheckCPUID
)

// Config controls which vendors and detection dimensions are evaluated.
//
// Zero-value Config uses all defaults:
//
//	cfg := antivm.Config{}            // nil Vendors → DefaultVendors, 0 Checks → CheckAll
//	cfg := antivm.DefaultConfig()     // equivalent
//
// Restrict to specific vendors and checks:
//
//	cfg := antivm.Config{
//	    Vendors: []antivm.Vendor{{Name: "VMware", Nic: []string{"00:0C:29"}}},
//	    Checks:  antivm.CheckNIC | antivm.CheckFiles,
//	}
type Config struct {
	// Vendors to scan. Nil means use the platform DefaultVendors.
	Vendors []Vendor
	// Checks selects which detection dimensions to run. Zero means CheckAll.
	Checks CheckType
}

// DefaultConfig returns a zero-value Config which uses DefaultVendors and CheckAll.
func DefaultConfig() Config { return Config{} }

// vendors returns the effective vendor list, falling back to DefaultVendors.
func (c Config) vendors() []Vendor {
	if c.Vendors != nil {
		return c.Vendors
	}
	return DefaultVendors
}

// checks returns the effective bitmask, falling back to CheckAll.
func (c Config) checks() CheckType {
	if c.Checks == 0 {
		return CheckAll
	}
	return c.Checks
}
