//go:build windows

package stealthopen_test

import (
	"fmt"
	"io"

	"github.com/oioio-space/maldev/evasion/stealthopen"
)

// GetObjectID reads the 128-bit NTFS Object ID from the MFT entry.
// First call goes through path-based hooks; reuse the GUID afterwards
// to bypass them.
func ExampleGetObjectID() {
	oid, err := stealthopen.GetObjectID(`C:\Windows\System32\ntdll.dll`)
	if err != nil {
		fmt.Println("get:", err)
		return
	}
	fmt.Printf("Object ID: %x\n", oid)
}

// OpenByID opens the file by volume + Object ID — the access does NOT
// surface to path-watching filter drivers.
func ExampleOpenByID() {
	oid, _ := stealthopen.GetObjectID(`C:\Windows\System32\ntdll.dll`)
	f, err := stealthopen.OpenByID(`C:\`, oid)
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer f.Close()
	data, _ := io.ReadAll(f)
	fmt.Printf("read %d bytes\n", len(data))
}

// OpenRead is the high-level helper combining GetObjectID + OpenByID.
// Pass a Stealth Opener for the GUID path; nil falls back to Standard
// (path-based read — useful for testing).
func ExampleOpenRead() {
	data, err := stealthopen.OpenRead(&stealthopen.Stealth{}, `C:\Windows\System32\ntdll.dll`)
	if err != nil {
		fmt.Println("read:", err)
		return
	}
	fmt.Printf("ntdll size: %d bytes\n", len(data))
}
