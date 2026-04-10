//go:build windows

package drive

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

// logicalDrivesMask returns the raw GetLogicalDrives bitmask.
// Used by watchWorker for fast comparison before expensive enumeration.
func logicalDrivesMask() (uint32, error) {
	return windows.GetLogicalDrives()
}

// LogicalDriveLetters returns the drive letters present on the machine.
func LogicalDriveLetters() ([]string, error) {
	mask, err := logicalDrivesMask()
	if err != nil {
		return nil, err
	}
	var letters []string
	for _, l := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		if mask&1 == 1 {
			letters = append(letters, string(l)+":\\")
		}
		mask >>= 1
	}
	return letters, nil
}

// TypeOf returns the drive Type for a root path (e.g., "C:\\").
// GetDriveTypeW never fails — it returns TypeUnknown for invalid paths.
func TypeOf(root string) Type {
	d, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return TypeUnknown
	}
	return Type(windows.GetDriveType(d))
}

// VolumeOf returns volume metadata for a drive root path (e.g., "C:\\").
func VolumeOf(root string) (*VolumeInfo, error) {
	d, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return nil, err
	}

	volumeName := make([]uint16, syscall.MAX_PATH+1)
	var serialNumber uint32
	var maxComponentLen uint32
	var fsFlags uint32
	fsName := make([]uint16, syscall.MAX_PATH+1)

	err = windows.GetVolumeInformation(
		d,
		&volumeName[0], uint32(len(volumeName)),
		&serialNumber,
		&maxComponentLen,
		&fsFlags,
		&fsName[0], uint32(len(fsName)),
	)
	if err != nil {
		return nil, err
	}

	return &VolumeInfo{
		Name:           syscall.UTF16ToString(volumeName),
		SerialNumber:   serialNumber,
		FileSystemName: syscall.UTF16ToString(fsName),
	}, nil
}

// volumeGUID returns the volume GUID path (\\?\Volume{...}\) for a drive
// letter. Returns empty string if unavailable (e.g., no media in drive).
func volumeGUID(root string) string {
	rootPtr, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return ""
	}
	buf := make([]uint16, 50) // GUID path is ~49 chars
	err = windows.GetVolumeNameForVolumeMountPoint(rootPtr, &buf[0], uint32(len(buf)))
	if err != nil {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

// devicePath returns the NT device path (\Device\HarddiskVolumeN) for a
// drive letter. Uses QueryDosDevice. Returns empty string if unavailable.
func devicePath(root string) string {
	// QueryDosDevice expects "C:" not "C:\"
	dosName := root
	if len(dosName) >= 2 && dosName[len(dosName)-1] == '\\' {
		dosName = dosName[:len(dosName)-1]
	}
	namePtr, err := syscall.UTF16PtrFromString(dosName)
	if err != nil {
		return ""
	}
	buf := make([]uint16, syscall.MAX_PATH)
	n, err := queryDosDevice(namePtr, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}

var procQueryDosDeviceW = api.Kernel32.NewProc("QueryDosDeviceW")

// queryDosDevice wraps QueryDosDeviceW. Returns the number of chars written.
func queryDosDevice(deviceName *uint16, targetPath *uint16, maxLen uint32) (uint32, error) {
	r, _, e := procQueryDosDeviceW.Call(
		uintptr(unsafe.Pointer(deviceName)),
		uintptr(unsafe.Pointer(targetPath)),
		uintptr(maxLen),
	)
	if r == 0 {
		return 0, fmt.Errorf("QueryDosDeviceW: %w", e)
	}
	return uint32(r), nil
}
