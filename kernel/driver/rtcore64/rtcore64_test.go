package rtcore64

import "testing"

// TestPackageConstants guards the well-known IOCTL codes and service
// name. These values are part of the BYOVD chain's stable surface —
// renaming them silently would break consumers that expect
// "\\.\RTCore64" or the documented IOCTL ranges.
func TestPackageConstants(t *testing.T) {
	if ServiceName != "RTCore64" {
		t.Errorf("ServiceName = %q, want %q", ServiceName, "RTCore64")
	}
	if DevicePath != `\\.\RTCore64` {
		t.Errorf("DevicePath = %q, want \\\\.\\RTCore64", DevicePath)
	}
	if IoctlRead != 0x80002048 {
		t.Errorf("IoctlRead = 0x%X, want 0x80002048", IoctlRead)
	}
	if IoctlWrite != 0x8000204C {
		t.Errorf("IoctlWrite = 0x%X, want 0x8000204C", IoctlWrite)
	}
	if MaxPrimitiveBytes != 4096 {
		t.Errorf("MaxPrimitiveBytes = %d, want 4096", MaxPrimitiveBytes)
	}
}

// TestDriverZeroValueLoadedFalse ensures Loaded() reports false on a
// fresh Driver — required so callers can branch on Loaded() before
// committing to Install/Uninstall.
func TestDriverZeroValueLoadedFalse(t *testing.T) {
	var d Driver
	if d.Loaded() {
		t.Error("zero Driver.Loaded() = true, want false")
	}
}

// TestDriverErrDriverBytesMissingExported keeps the sentinel error
// reachable on every platform — non-Windows aliases it to
// driver.ErrNotImplemented so cross-platform code can switch on either.
func TestDriverErrDriverBytesMissingExported(t *testing.T) {
	if ErrDriverBytesMissing == nil {
		t.Fatal("ErrDriverBytesMissing is nil")
	}
}
