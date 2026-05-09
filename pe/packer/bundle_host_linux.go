//go:build amd64 && linux

package packer

import "golang.org/x/sys/unix"

// mmapRX returns a fresh PROT_READ|WRITE|EXEC, MAP_ANON|PRIVATE page
// of at least size bytes. Linux backend.
func mmapRX(size int) []byte {
	mem, err := unix.Mmap(-1, 0, size,
		unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,
		unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		panic("packer: mmap RX: " + err.Error())
	}
	return mem
}

// hostWinBuild always returns 0 on Linux — there is no PEB, and Windows
// build-number predicates do not apply. Bundles that target Linux
// should leave PT_WIN_BUILD unset on every entry.
func hostWinBuild() uint32 { return 0 }
