//go:build windows && amd64

package kcallback

import (
	"strings"
	"testing"
	"unsafe"
)

// TestNtoskrnlBase_Resolves asserts the user-mode query succeeds and
// yields a non-zero kernel VA. Any BOOT value > 0 is structurally
// valid; kernel addresses live in the canonical high range on x64.
func TestNtoskrnlBase_Resolves(t *testing.T) {
	base, err := NtoskrnlBase()
	if err != nil {
		t.Fatalf("NtoskrnlBase: %v", err)
	}
	if base == 0 {
		t.Fatal("NtoskrnlBase returned zero")
	}
	// x64 kernel VAs start in the canonical high half; low addresses
	// would indicate a usermode mixup.
	if base < 0xFFFF000000000000 {
		t.Fatalf("NtoskrnlBase 0x%X is not in the canonical high half", base)
	}
}

// TestDriverAt_ResolvesNtoskrnl confirms DriverAt resolves a
// known-in-kernel address (ntoskrnl's own base) back to ntoskrnl.exe.
func TestDriverAt_ResolvesNtoskrnl(t *testing.T) {
	base, err := NtoskrnlBase()
	if err != nil {
		t.Fatalf("NtoskrnlBase: %v", err)
	}
	name, err := DriverAt(base)
	if err != nil {
		t.Fatalf("DriverAt(0x%X): %v", base, err)
	}
	if !strings.EqualFold(name, "ntoskrnl.exe") {
		t.Fatalf("DriverAt(ntoskrnl.base) = %q, want ntoskrnl.exe", name)
	}
}

// TestDriverAt_ReturnsEmptyForUsermode asserts a userland address
// (this test's own stack) resolves to "" + nil — no driver should
// cover it.
func TestDriverAt_ReturnsEmptyForUsermode(t *testing.T) {
	var stackLocal int
	name, err := DriverAt(uintptr(unsafe.Pointer(&stackLocal)))
	if err != nil {
		t.Fatalf("DriverAt(stack): %v", err)
	}
	if name != "" {
		t.Fatalf("DriverAt(stack) = %q, want empty", name)
	}
}
