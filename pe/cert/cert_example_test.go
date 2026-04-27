package cert_test

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/cert"
)

// Read inspects the PE security directory and returns the raw
// WIN_CERTIFICATE blob (or nil + ErrNoCertificate when the file
// is unsigned).
func ExampleRead() {
	c, err := cert.Read(`C:\Windows\System32\notepad.exe`)
	if err != nil {
		return
	}
	fmt.Printf("certificate: %d bytes\n", len(c.Raw))
}

// Copy lifts the certificate blob from srcPE and appends it to
// dstPE, patching dstPE's security directory entry. Detection-wise
// the on-disk file becomes a "signed" PE — the signature itself
// fails verification (`signtool verify`), but file-property
// dialogs and naive metadata audits accept it.
func ExampleCopy() {
	if err := cert.Copy(
		`C:\Windows\System32\notepad.exe`,
		`C:\Users\Public\implant.exe`,
	); err != nil {
		return
	}
}
