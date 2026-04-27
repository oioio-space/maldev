package sekurlsa_test

import (
	"fmt"

	"github.com/oioio-space/maldev/credentials/sekurlsa"
)

// ParseFile reads a LSASS minidump and walks the MSV1_0 / Wdigest /
// Kerberos / DPAPI / TSPkg / CloudAP / LiveSSP / CredMan tables.
// Returns Result with credentials grouped per LUID.
func ExampleParseFile() {
	res, err := sekurlsa.ParseFile(`/tmp/lsass.dmp`, nil)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	_ = res // walk res.Sessions, res.Sessions[i].Credentials, etc.
}
