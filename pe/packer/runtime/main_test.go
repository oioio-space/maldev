package runtime_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/runtime"
)

func TestMain(m *testing.M) {
	if os.Getenv("MALDEV_PACKER_E2E_INNER") == "1" {
		runE2EFixtureAndExit()
	}
	os.Exit(m.Run())
}

func runE2EFixtureAndExit() {
	elf, err := os.ReadFile("testdata/hello_static_pie")
	if err != nil {
		fmt.Fprintln(os.Stderr, "E2E inner: read fixture:", err)
		os.Exit(2)
	}
	img, err := runtime.Prepare(elf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "E2E inner: Prepare:", err)
		os.Exit(2)
	}
	if err := img.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "E2E inner: Run:", err)
		os.Exit(2)
	}
	// Run() only returns if the loaded binary returns (unlikely
	// for a well-formed Go static-PIE that calls exit_group).
	// Exit cleanly so the outer test sees exit 0.
	os.Exit(0)
}
