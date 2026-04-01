//go:build windows

// Package drive provides drive detection and monitoring.
package drive

import (
	"context"
	"crypto/md5"
	"fmt"
	"time"
)

// DRIVETYPE represents a Windows drive type.
type DRIVETYPE uint32

// String returns a human-readable representation of the drive type.
func (wdt DRIVETYPE) String() string {
	switch wdt {
	case UNKNOWN:
		return "unknown"
	case NOROOTDIR:
		return "noRootDir"
	case REMOVABLE:
		return "removable"
	case FIXED:
		return "fixe"
	case REMOTE:
		return "remote"
	case CDROM:
		return "cdrom"
	case RAMDISK:
		return "ramdisk"
	default:
		return ""
	}
}

const (
	UNKNOWN   DRIVETYPE = 0
	NOROOTDIR DRIVETYPE = 1
	REMOVABLE DRIVETYPE = 2
	FIXED     DRIVETYPE = 3
	REMOTE    DRIVETYPE = 4
	CDROM     DRIVETYPE = 5
	RAMDISK   DRIVETYPE = 6
)

// VolumeInformations contains volume metadata.
type VolumeInformations struct {
	Name           string
	SerialNumber   int
	FileSystemName string
}

// NewVolumeInformations creates a new VolumeInformations.
func NewVolumeInformations(name string, serialNumber int, fsName string) *VolumeInformations {
	return &VolumeInformations{
		Name:           name,
		SerialNumber:   serialNumber,
		FileSystemName: fsName,
	}
}

// Drive represents a disk drive.
type Drive struct {
	Letter string
	Type   DRIVETYPE
	Infos  *VolumeInformations
	UID    [16]byte
}

// NewDrive creates a new Drive from a drive letter.
func NewDrive(letter string) (*Drive, error) {
	d := &Drive{
		Letter: letter,
	}

	var err error
	d.Infos, err = GetVolumeInformation(letter)
	if err != nil {
		return nil, err
	}

	d.Type, err = GetLogicalDriveType(letter)
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

// GetAll returns all drives matching the filter.
func (d *Drives) GetAll(ff FilterFunc) ([]*Drive, error) {
	ldl, err := GetLogicalDrivesLetter()
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

// GetNew returns newly connected drives since last check.
func (d *Drives) GetNew(ff FilterFunc, appendNew bool) ([]*Drive, error) {
	nDrives := make([]*Drive, 0)

	ldl, err := GetLogicalDrivesLetter()
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
	_, err := d.GetAll(ff)
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
			drives, err := d.GetNew(ff, once)
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
