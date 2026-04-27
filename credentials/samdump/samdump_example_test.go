package samdump_test

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/credentials/samdump"
)

// Dump parses offline SAM + SYSTEM hives. Hives are typically obtained
// via `reg save HKLM\SAM C:\sam` / `reg save HKLM\SYSTEM C:\system`.
func ExampleDump() {
	system, err := os.Open(`/tmp/SYSTEM`)
	if err != nil {
		return
	}
	defer system.Close()
	sam, err := os.Open(`/tmp/SAM`)
	if err != nil {
		return
	}
	defer sam.Close()
	sysFI, _ := system.Stat()
	samFI, _ := sam.Stat()

	res, err := samdump.Dump(system, sysFI.Size(), sam, samFI.Size())
	if err != nil {
		fmt.Println("dump:", err)
		return
	}
	_ = res // walk res.Accounts (RID, NT, LM, etc.)
}
