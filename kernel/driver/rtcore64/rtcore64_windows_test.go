//go:build windows

package rtcore64

import (
	"errors"
	"testing"

	"github.com/oioio-space/maldev/kernel/driver"
)

// TestInstallWithoutEmbeddedBytes verifies the default-build path
// surfaces ErrDriverBytesMissing rather than producing partial state.
// Run on every platform — no admin required because the error fires
// before SCM is touched.
func TestInstallWithoutEmbeddedBytes(t *testing.T) {
	var d Driver
	err := d.Install()
	if !errors.Is(err, ErrDriverBytesMissing) {
		t.Fatalf("Install() err = %v, want ErrDriverBytesMissing", err)
	}
	if d.Loaded() {
		t.Error("Loaded() = true after failed Install")
	}
}

// TestReadKernelNotLoadedReturnsErrNotLoaded keeps callers honest:
// reading before Install must surface a clear error, not a Windows
// HANDLE-zero error string from DeviceIoControl.
func TestReadKernelNotLoadedReturnsErrNotLoaded(t *testing.T) {
	var d Driver
	buf := make([]byte, 8)
	n, err := d.ReadKernel(0xDEADBEEF, buf)
	if !errors.Is(err, driver.ErrNotLoaded) {
		t.Errorf("ReadKernel err = %v, want driver.ErrNotLoaded", err)
	}
	if n != 0 {
		t.Errorf("ReadKernel n = %d, want 0", n)
	}
}

// TestWriteKernelNotLoadedReturnsErrNotLoaded mirrors the read-side
// contract for the write primitive.
func TestWriteKernelNotLoadedReturnsErrNotLoaded(t *testing.T) {
	var d Driver
	n, err := d.WriteKernel(0xDEADBEEF, []byte{0x90, 0x90})
	if !errors.Is(err, driver.ErrNotLoaded) {
		t.Errorf("WriteKernel err = %v, want driver.ErrNotLoaded", err)
	}
	if n != 0 {
		t.Errorf("WriteKernel n = %d, want 0", n)
	}
}

// TestUninstallIdempotentOnZeroDriver is a smoke test that Uninstall on
// a never-installed Driver is a clean no-op (no SCM call, no error).
// We can't observe SCM directly without admin, but the device-handle
// branch is skipped (handle=0) and the dropped-file branch is skipped
// (servicePath=""), so only stopAndDeleteService runs — and that
// returns nil whenever the service is absent.
func TestUninstallIdempotentOnZeroDriver(t *testing.T) {
	var d Driver
	if err := d.Uninstall(); err != nil {
		t.Errorf("Uninstall on zero Driver = %v, want nil", err)
	}
}

// TestReadKernelExceedsMaxPrimitiveReturnsError prevents accidental
// large transfers — RTCore64 hangs the kernel pool on > 4 KiB
// transfers, so we surface the limit before issuing the IOCTL.
func TestReadKernelExceedsMaxPrimitiveReturnsError(t *testing.T) {
	d := Driver{device: 1} // simulate "loaded" without admin
	defer func() { d.device = 0 }()
	buf := make([]byte, MaxPrimitiveBytes+1)
	_, err := d.ReadKernel(0x1000, buf)
	if err == nil {
		t.Fatal("ReadKernel oversized = nil err, want length-cap error")
	}
}

// TestWriteKernelExceedsMaxPrimitiveReturnsError mirrors the read-side
// length cap for the write primitive.
func TestWriteKernelExceedsMaxPrimitiveReturnsError(t *testing.T) {
	d := Driver{device: 1}
	defer func() { d.device = 0 }()
	data := make([]byte, MaxPrimitiveBytes+1)
	_, err := d.WriteKernel(0x1000, data)
	if err == nil {
		t.Fatal("WriteKernel oversized = nil err, want length-cap error")
	}
}
