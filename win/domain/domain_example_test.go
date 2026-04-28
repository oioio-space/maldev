//go:build windows

package domain_test

import (
	"fmt"

	"github.com/oioio-space/maldev/win/domain"
)

// Name returns the host's domain or workgroup name plus the join
// status — gate domain-targeted post-ex flows on this before
// expanding operations.
func ExampleName() {
	name, status, err := domain.Name()
	if err != nil {
		fmt.Println("domain:", err)
		return
	}
	if status == domain.StatusDomain {
		fmt.Printf("joined: %s\n", name)
	}
}
