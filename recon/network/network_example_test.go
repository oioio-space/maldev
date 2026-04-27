package network_test

import (
	"fmt"

	"github.com/oioio-space/maldev/recon/network"
)

// InterfaceIPs returns every IP across every interface
// (loopback + physical + virtual). Useful for sandbox
// fingerprinting and source-IP-aware C2.
func ExampleInterfaceIPs() {
	ips, err := network.InterfaceIPs()
	if err != nil {
		return
	}
	for _, ip := range ips {
		fmt.Println(ip.String())
	}
}

// IsLocal returns true when the input (IP / hostname / FQDN)
// resolves to one of the host's own interfaces.
func ExampleIsLocal() {
	ok, err := network.IsLocal("127.0.0.1")
	if err != nil {
		return
	}
	fmt.Println("local:", ok)
}
