//go:build windows

package lsassdump

import (
	"fmt"

	"github.com/oioio-space/maldev/recon/folder"
)

// defaultNtoskrnlPath resolves an empty `path` to the kernel image
// inside `%SystemRoot%\System32`.
//
// Resolution goes through recon/folder.Get(CSIDL_SYSTEM) — i.e.
// SHGetSpecialFolderPathW(Shell32) — instead of os.Getenv("SystemRoot")
// to avoid the PEB env-var sniff that EDRs commonly log. `caller`
// names the public entry point so the error message points at the
// right export when the resolution fails.
func defaultNtoskrnlPath(path, caller string) (string, error) {
	if path != "" {
		return path, nil
	}
	system32 := folder.Get(folder.CSIDL_SYSTEM, false)
	if system32 == "" {
		return "", fmt.Errorf("%s: SHGetSpecialFolderPathW(CSIDL_SYSTEM) returned empty", caller)
	}
	return system32 + `\ntoskrnl.exe`, nil
}
