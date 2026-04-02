// Package wipe provides secure file wiping.
package wipe

import (
	"crypto/rand"
	"fmt"
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
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for pass := 0; pass < passes; pass++ {
		if _, err := f.Seek(0, 0); err != nil {
			f.Close()
			return fmt.Errorf("seek pass %d: %w", pass+1, err)
		}
		written := int64(0)
		for written < size {
			n := int64(len(buf))
			if size-written < n {
				n = size - written
			}
			if _, err := rand.Read(buf[:n]); err != nil {
				f.Close()
				return fmt.Errorf("random read pass %d: %w", pass+1, err)
			}
			nw, werr := f.Write(buf[:n])
			if werr != nil {
				f.Close()
				return fmt.Errorf("write pass %d: %w", pass+1, werr)
			}
			written += int64(nw)
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return fmt.Errorf("sync pass %d: %w", pass+1, err)
		}
	}
	// Close before Remove — Windows requires the handle to be released.
	f.Close()
	return os.Remove(path)
}
