//go:build windows

package lsassdump

import (
	"fmt"

	"github.com/oioio-space/maldev/recon/folder"
	"golang.org/x/sys/windows"
)

// defaultNtoskrnlPath resolves an empty `path` to the kernel image
// inside `%SystemRoot%\System32`.
//
// Resolution goes through recon/folder.GetKnown(FOLDERID_System) — i.e.
// SHGetKnownFolderPath(Shell32) — instead of os.Getenv("SystemRoot")
// to avoid the PEB env-var sniff that EDRs commonly log. `caller`
// names the public entry point so the error message points at the
// right export when the resolution fails.
func defaultNtoskrnlPath(path, caller string) (string, error) {
	if path != "" {
		return path, nil
	}
	system32, err := folder.GetKnown(windows.FOLDERID_System, 0)
	if err != nil {
		return "", fmt.Errorf("%s: SHGetKnownFolderPath(FOLDERID_System): %w", caller, err)
	}
	return system32 + `\ntoskrnl.exe`, nil
}
