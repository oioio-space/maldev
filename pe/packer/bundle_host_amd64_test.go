//go:build amd64 && (linux || windows)

package packer_test

import (
	"bufio"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestHostCPUIDVendor_MatchesProcCPUInfo asserts the asm reader's output
// equals what the Linux kernel reports under /proc/cpuinfo's vendor_id.
//
// Skipped on Windows because Windows lacks /proc; the Windows path is
// covered indirectly by the bundle E2E (run on a Win VM, fingerprint
// matches against a known-vendor entry).
func TestHostCPUIDVendor_MatchesProcCPUInfo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires /proc/cpuinfo")
	}
	got := packer.HostCPUIDVendor()
	want := procCPUVendor(t)
	if string(got[:]) != want {
		t.Errorf("HostCPUIDVendor = %q, want %q (from /proc/cpuinfo)", got[:], want)
	}
}

// TestMatchBundleHost_PicksMatchingVendor builds a 2-payload bundle
// targeting the host's actual CPUID vendor + a wildcard fallback,
// then asserts MatchBundleHost selects payload 0.
func TestMatchBundleHost_PicksMatchingVendor(t *testing.T) {
	hostVendor := packer.HostCPUIDVendor()
	if hostVendor == ([12]byte{}) {
		t.Skip("CPUID vendor read returned zero — non-x86 host?")
	}

	pls := []packer.BundlePayload{
		{Binary: []byte("targeted"), Fingerprint: packer.FingerprintPredicate{
			PredicateType: packer.PTCPUIDVendor,
			VendorString:  hostVendor,
		}},
		{Binary: []byte("fallback"), Fingerprint: packer.FingerprintPredicate{
			PredicateType: packer.PTMatchAll,
		}},
	}
	bundle, err := packer.PackBinaryBundle(pls, packer.BundleOptions{})
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	idx, err := packer.MatchBundleHost(bundle)
	if err != nil {
		t.Fatalf("MatchBundleHost: %v", err)
	}
	if idx != 0 {
		t.Errorf("MatchBundleHost = %d, want 0 (host-vendor entry)", idx)
	}
}

// TestMatchBundleHost_FallsBackToWildcard wires up a bundle with a
// vendor that cannot match any plausible host CPU and asserts the
// PTMatchAll fallback fires.
func TestMatchBundleHost_FallsBackToWildcard(t *testing.T) {
	bogus := [12]byte{'N', 'o', 't', 'A', 'R', 'e', 'a', 'l', 'C', 'P', 'U', '!'}
	pls := []packer.BundlePayload{
		{Binary: []byte("targeted"), Fingerprint: packer.FingerprintPredicate{
			PredicateType: packer.PTCPUIDVendor,
			VendorString:  bogus,
		}},
		{Binary: []byte("fallback"), Fingerprint: packer.FingerprintPredicate{
			PredicateType: packer.PTMatchAll,
		}},
	}
	bundle, _ := packer.PackBinaryBundle(pls, packer.BundleOptions{})
	idx, err := packer.MatchBundleHost(bundle)
	if err != nil {
		t.Fatalf("MatchBundleHost: %v", err)
	}
	if idx != 1 {
		t.Errorf("MatchBundleHost = %d, want 1 (wildcard fallback)", idx)
	}
}

func procCPUVendor(t *testing.T) string {
	t.Helper()
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		t.Skipf("cannot open /proc/cpuinfo: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "vendor_id") {
			if i := strings.Index(line, ":"); i != -1 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	t.Skip("vendor_id not in /proc/cpuinfo")
	return ""
}
