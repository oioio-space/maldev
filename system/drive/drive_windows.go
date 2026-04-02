//go:build windows

package drive

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// LogicalDriveLetters returns the drive letters present on the machine.
func LogicalDriveLetters() (d []string, err error) {
	bitMap, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, err
	}
	for _, l := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		if bitMap&1 == 1 {
			d = append(d, string(l)+":\\")
		}
		bitMap >>= 1
	}
	return d, nil
}

// Type returns the DriveType for a given drive letter.
func Type(drive string) (DriveType, error) {
	d, err := syscall.UTF16PtrFromString(drive)
	if err != nil {
		return 0, err
	}
	return DriveType(windows.GetDriveType(d)), nil
}

// Volume returns volume metadata for a given drive letter.
func Volume(drive string) (*VolumeInfo, error) {
	volumeNameBuffer := make([]uint16, syscall.MAX_PATH+1)
	nVolumeNameSize := uint32(len(volumeNameBuffer))
	var volumeSerialNumber uint32
	var maximumComponentLength uint32
	var fileSystemFlags uint32
	fileSystemNameBuffer := make([]uint16, syscall.MAX_PATH+1)
	nFileSystemNameSize := uint32(syscall.MAX_PATH + 1)

	d, err := syscall.UTF16PtrFromString(drive)
	if err != nil {
		return nil, err
	}

	err = windows.GetVolumeInformation(
		d,
		&volumeNameBuffer[0],
		nVolumeNameSize,
		&volumeSerialNumber,
		&maximumComponentLength,
		&fileSystemFlags,
		&fileSystemNameBuffer[0],
		nFileSystemNameSize,
	)
	if err != nil {
		return nil, err
	}

	return NewVolumeInfo(
		syscall.UTF16ToString(volumeNameBuffer),
		int(volumeSerialNumber),
		syscall.UTF16ToString(fileSystemNameBuffer),
	), nil
}
