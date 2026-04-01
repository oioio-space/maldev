// Package timestomp provides file timestamp manipulation.
package timestomp

import (
	"os"
	"time"
)

// Set changes the access and modification times of a file.
func Set(path string, atime, mtime time.Time) error {
	return os.Chtimes(path, atime, mtime)
}

// CopyFrom copies the timestamps from src file to dst file.
func CopyFrom(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.Chtimes(dst, info.ModTime(), info.ModTime())
}
