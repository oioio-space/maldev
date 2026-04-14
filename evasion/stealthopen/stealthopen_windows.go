//go:build windows

package stealthopen

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

const (
	fsctlCreateOrGetObjectID = 0x900C0
	fsctlSetObjectID         = 0x900A4
	fileShareAll             = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
)

// fileObjectIDBuf mirrors FILE_OBJECTID_BUFFER (64 bytes).
type fileObjectIDBuf struct {
	ObjectID      [16]byte
	BirthVolumeID [16]byte
	BirthObjectID [16]byte
	DomainID      [16]byte
}

// fileIDDescriptor mirrors FILE_ID_DESCRIPTOR for ObjectId type.
// DwSize=24, IDType=1 (ObjectIdType), ObjectID=[16]byte
type fileIDDescriptor struct {
	DwSize   uint32
	IDType   uint32 // 1 = ObjectIdType
	ObjectID [16]byte
}

var procOpenFileByID = api.Kernel32.NewProc("OpenFileById")

// GetObjectID returns the NTFS Object ID of a file, creating one if absent.
func GetObjectID(path string) ([16]byte, error) {
	h, err := openForFsctl(path)
	if err != nil {
		return [16]byte{}, err
	}
	defer windows.CloseHandle(h)

	var buf fileObjectIDBuf
	var returned uint32
	if err = windows.DeviceIoControl(h,
		fsctlCreateOrGetObjectID,
		nil, 0,
		(*byte)(unsafe.Pointer(&buf)), uint32(unsafe.Sizeof(buf)),
		&returned, nil,
	); err != nil {
		return [16]byte{}, fmt.Errorf("FSCTL_CREATE_OR_GET_OBJECT_ID: %w", err)
	}
	return buf.ObjectID, nil
}

// SetObjectID assigns a specific NTFS Object ID to a file. Requires admin.
func SetObjectID(path string, objectID [16]byte) error {
	h, err := openForFsctl(path)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	buf := fileObjectIDBuf{ObjectID: objectID}
	var returned uint32
	return windows.DeviceIoControl(h,
		fsctlSetObjectID,
		(*byte)(unsafe.Pointer(&buf)), uint32(unsafe.Sizeof(buf)),
		nil, 0,
		&returned, nil,
	)
}

// OpenByID opens a file using its NTFS Object ID, bypassing path-based EDR hooks.
// volumePath is the volume root, e.g. `C:\`.
func OpenByID(volumePath string, objectID [16]byte) (*os.File, error) {
	volPath, err := windows.UTF16PtrFromString(volumePath)
	if err != nil {
		return nil, fmt.Errorf("encode volume path: %w", err)
	}

	hVol, err := windows.CreateFile(
		volPath,
		windows.GENERIC_READ,
		fileShareAll,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open volume %s: %w", volumePath, err)
	}
	defer windows.CloseHandle(hVol)

	desc := fileIDDescriptor{
		DwSize:   uint32(unsafe.Sizeof(fileIDDescriptor{})),
		IDType:   1, // ObjectIdType
		ObjectID: objectID,
	}

	h, _, callErr := procOpenFileByID.Call(
		uintptr(hVol),
		uintptr(unsafe.Pointer(&desc)),
		uintptr(windows.GENERIC_READ),
		uintptr(fileShareAll),
		0,
		uintptr(windows.FILE_FLAG_BACKUP_SEMANTICS),
	)
	if windows.Handle(h) == windows.InvalidHandle {
		return nil, fmt.Errorf("OpenFileById: %w", callErr)
	}

	return os.NewFile(h, "objectid"), nil
}

// openForFsctl opens a file handle suitable for DeviceIoControl FSCTL operations.
func openForFsctl(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("encode path: %w", err)
	}
	h, err := windows.CreateFile(
		p,
		windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES,
		fileShareAll,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("open file for fsctl: %w", err)
	}
	return h, nil
}
