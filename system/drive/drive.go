//go:build windows

// Package drive provides drive detection and monitoring.
package drive

import (
	"context"
	"crypto/md5"
	"fmt"
	"time"
)

// DriveType represents a Windows drive type.
type DriveType uint32

// String returns a human-readable representation of the drive type.
func (wdt DriveType) String() string {
	switch wdt {
	case Unknown:
		return "unknown"
	case NoRootDir:
		return "noRootDir"
	case Removable:
		return "removable"
	case Fixed:
		return "fixed"
	case Remote:
		return "remote"
	case CDROM:
		return "cdrom"
	case RAMDisk:
		return "ramdisk"
	default:
		return ""
	}
}

const (
	Unknown   DriveType = 0
	NoRootDir DriveType = 1
	Removable DriveType = 2
	Fixed     DriveType = 3
	Remote    DriveType = 4
	CDROM     DriveType = 5
	RAMDisk   DriveType = 6
)

// VolumeInfo contains volume metadata.
type VolumeInfo struct {
	Name           string
	SerialNumber   int
	FileSystemName string
}

// NewVolumeInfo creates a new VolumeInfo.
func NewVolumeInfo(name string, serialNumber int, fsName string) *VolumeInfo {
	return &VolumeInfo{
		Name:           name,
		SerialNumber:   serialNumber,
		FileSystemName: fsName,
	}
}

// Drive represents a disk drive.
type Drive struct {
	Letter string
	Type   DriveType
	Infos  *VolumeInfo
	UID    [16]byte
}

// NewDrive creates a new Drive from a drive letter.
func NewDrive(letter string) (*Drive, error) {
	d := &Drive{
		Letter: letter,
	}

	var err error
	d.Infos, err = Volume(letter)
	if err != nil {
		return nil, err
	}

	d.Type, err = Type(letter)
	if err != nil {
		return nil, err
	}

	d.UID = md5.Sum([]byte(fmt.Sprintf("%s-%d-%s", d.Type, d.Infos.SerialNumber, d.Infos.FileSystemName)))

	return d, nil
}

// FilterFunc is a callback to filter drives.
type FilterFunc func(drive *Drive) bool

// Drives manages a collection of detected drives.
type Drives struct {
	List      map[[16]byte]*Drive
	chanDrive chan any
	ctx       context.Context
}

// NewDrives creates a new Drives manager.
func NewDrives(ctx context.Context) *Drives {
	return &Drives{
		List: make(map[[16]byte]*Drive),
		ctx:  ctx,
	}
}

func (d *Drives) mapToArray() []*Drive {
	drives := make([]*Drive, 0)
	for _, v := range d.List {
		drives = append(drives, v)
	}
	return drives
}

// All returns all drives matching the filter.
func (d *Drives) All(ff FilterFunc) ([]*Drive, error) {
	ldl, err := LogicalDriveLetters()
	if err != nil {
		return nil, err
	}

	for _, l := range ldl {
		drive, err := NewDrive(l)
		if err != nil {
			continue
		}
		if ff(drive) {
			d.List[drive.UID] = drive
		}
	}
	return d.mapToArray(), nil
}

// Added returns newly connected drives since last check.
func (d *Drives) Added(ff FilterFunc, appendNew bool) ([]*Drive, error) {
	nDrives := make([]*Drive, 0)

	ldl, err := LogicalDriveLetters()
	if err != nil {
		return nil, err
	}

	for _, l := range ldl {
		drive, err := NewDrive(l)
		if err != nil {
			continue
		}
		if ff(drive) {
			if _, ok := d.List[drive.UID]; ok {
				continue
			}
			if appendNew {
				d.List[drive.UID] = drive
			}
			nDrives = append(nDrives, drive)
		}
	}
	return nDrives, nil
}

// WatchNew starts a goroutine that monitors for new drives matching the filter.
func (d *Drives) WatchNew(ff FilterFunc, once bool) (<-chan any, error) {
	_, err := d.All(ff)
	if err != nil {
		return nil, err
	}

	d.chanDrive = make(chan any)
	go d.watchNewWorker(ff, once)

	return d.chanDrive, nil
}

func (d *Drives) watchNewWorker(ff FilterFunc, once bool) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	defer close(d.chanDrive)

	bkpDrives := make(map[[16]byte]*Drive)
	tmpDrives := make(map[[16]byte]*Drive)

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			drives, err := d.Added(ff, once)
			if err != nil {
				d.chanDrive <- err
				continue
			}

			tmpDrives = make(map[[16]byte]*Drive)
			for _, drive := range drives {
				tmpDrives[drive.UID] = drive
			}

			for _, drive := range tmpDrives {
				if _, okBkp := bkpDrives[drive.UID]; !okBkp {
					d.chanDrive <- drive
				}
			}

			bkpDrives = tmpDrives
		}
	}
}
