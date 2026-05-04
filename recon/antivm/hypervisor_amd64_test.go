//go:build amd64

package antivm

import (
	"encoding/binary"
	"testing"
)

// TestCpuidRaw_VendorLeaf verifies the asm wrapper round-trips
// correctly. Leaf 0 returns the CPU vendor string in EBX:EDX:ECX
// (note the EBX/EDX/ECX order — different from hypervisor leaf
// 0x40000000's EBX/ECX/EDX). Every amd64 CPU returns one of:
//
//	"GenuineIntel"
//	"AuthenticAMD"
//	"HygonGenuine"
//	"CentaurHauls" (VIA)
//	"  Shanghai  " (Zhaoxin)
//
// The test passes whenever the bytes are printable ASCII — a
// regression in the asm stub would either return all-zero (no
// CPUID executed) or garbage from the wrong registers.
func TestCpuidRaw_VendorLeaf(t *testing.T) {
	_, ebx, ecx, edx := cpuidRaw(0, 0)
	if ebx == 0 && ecx == 0 && edx == 0 {
		t.Fatal("cpuidRaw(0, 0) returned all-zero — asm stub is broken")
	}
	// CPU vendor leaf 0 returns the 12-byte signature in EBX:EDX:ECX
	// (note: hypervisor leaf 0x40000000 uses EBX:ECX:EDX — different
	// register order).
	var b [12]byte
	binary.LittleEndian.PutUint32(b[0:4], ebx)
	binary.LittleEndian.PutUint32(b[4:8], edx)
	binary.LittleEndian.PutUint32(b[8:12], ecx)
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			t.Fatalf("cpuidRaw(0, 0) returned non-printable vendor bytes: %q", b)
		}
	}
	t.Logf("CPU vendor: %q", b)
}

// TestCpuidRaw_HighestBasicLeaf checks that EAX from leaf 0
// (highest supported basic leaf) is at least 1 — the leaf we
// query for the hypervisor bit. Every CPU shipped since the
// original Pentium reports >= 1.
func TestCpuidRaw_HighestBasicLeaf(t *testing.T) {
	max, _, _, _ := cpuidRaw(0, 0)
	if max < 1 {
		t.Fatalf("cpuidRaw(0).EAX = %d, want >= 1", max)
	}
	t.Logf("CPU supports basic CPUID leaves up to 0x%X", max)
}
