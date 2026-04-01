// Package wipe provides secure file wiping.
package wipe

import (
	"crypto/rand"
	"os"
)

// File securely overwrites a file with random data before deleting it.
// Passes controls how many overwrite passes to perform (minimum 1).
func File(path string, passes int) error {
	if passes < 1 {
		passes = 1
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	size := info.Size()
	for i := 0; i < passes; i++ {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		buf := make([]byte, 4096)
		written := int64(0)
		for written < size {
			n := int64(len(buf))
			if size-written < n {
				n = size - written
			}
			rand.Read(buf[:n])
			f.Write(buf[:n])
			written += n
		}
		f.Sync()
		f.Close()
	}
	return os.Remove(path)
}
