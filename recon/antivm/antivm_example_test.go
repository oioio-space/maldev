package antivm_test

import (
	"fmt"

	"github.com/oioio-space/maldev/recon/antivm"
)

// Detect returns the first matching hypervisor name across the
// configured check dimensions, or empty when no VM is detected.
func ExampleDetect() {
	name, err := antivm.Detect(antivm.DefaultConfig())
	if err != nil || name == "" {
		return
	}
	fmt.Printf("running inside %s — bailing out\n", name)
}

// DetectAll returns every match — useful when more than one
// indicator may apply (Hyper-V + WSL, Docker + nested VM).
func ExampleDetectAll() {
	names, _ := antivm.DetectAll(antivm.DefaultConfig())
	for _, n := range names {
		fmt.Println(n)
	}
}
