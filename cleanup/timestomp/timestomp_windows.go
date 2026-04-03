//go:build windows

package timestomp

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

// CopyFromFull copies all three timestamps (creation, access, modification)
// from src to dst using Windows-native SetFileTime.
func CopyFromFull(src, dst string) error {
	srcPath, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return fmt.Errorf("encode src path: %w", err)
	}
	hSrc, err := windows.CreateFile(srcPath, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer windows.CloseHandle(hSrc)

	var ctime, atime, mtime windows.Filetime
	if err := windows.GetFileTime(hSrc, &ctime, &atime, &mtime); err != nil {
		return fmt.Errorf("get file time: %w", err)
	}

	dstPath, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return fmt.Errorf("encode dst path: %w", err)
	}
	hDst, err := windows.CreateFile(dstPath, windows.FILE_WRITE_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("open destination: %w", err)
	}
	defer windows.CloseHandle(hDst)

	if err := windows.SetFileTime(hDst, &ctime, &atime, &mtime); err != nil {
		return fmt.Errorf("set file time: %w", err)
	}
	return nil
}

// SetFull sets creation, access, and modification times on a file.
func SetFull(path string, ctime, atime, mtime time.Time) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode path: %w", err)
	}
	h, err := windows.CreateFile(p, windows.FILE_WRITE_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer windows.CloseHandle(h)

	ct := windows.NsecToFiletime(ctime.UnixNano())
	at := windows.NsecToFiletime(atime.UnixNano())
	mt := windows.NsecToFiletime(mtime.UnixNano())
	return windows.SetFileTime(h, &ct, &at, &mt)
}
