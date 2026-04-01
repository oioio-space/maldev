//go:build windows

package drive

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// GetLogicalDrivesLetter returns the drive letters present on the machine.
func GetLogicalDrivesLetter() (d []string, err error) {
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

// GetLogicalDriveType returns the DRIVETYPE for a given drive letter.
func GetLogicalDriveType(drive string) (DRIVETYPE, error) {
	d, err := syscall.UTF16PtrFromString(drive)
	if err != nil {
		return 0, err
	}
	return DRIVETYPE(windows.GetDriveType(d)), nil
}

// GetVolumeInformation returns volume metadata for a given drive letter.
func GetVolumeInformation(drive string) (*VolumeInformations, error) {
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

	return NewVolumeInformations(
		syscall.UTF16ToString(volumeNameBuffer),
		int(volumeSerialNumber),
		syscall.UTF16ToString(fileSystemNameBuffer),
	), nil
}
