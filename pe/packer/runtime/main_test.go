package runtime_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/runtime"
)

func TestMain(m *testing.M) {
	if os.Getenv("MALDEV_PACKER_E2E_INNER") == "1" {
		// MALDEV_PACKER_E2E_FIXTURE selects which testdata binary
		// the inner harness loads. Defaults to the Go static-PIE
		// (Stage C+D) so the original E2E path keeps its
		// zero-arg invocation. Stage E's non-Go fixture passes
		// "hello_static_pie_c" explicitly.
		fixture := os.Getenv("MALDEV_PACKER_E2E_FIXTURE")
		if fixture == "" {
			fixture = "hello_static_pie"
		}
		runE2EFixtureAndExit(fixture)
	}
	os.Exit(m.Run())
}

func runE2EFixtureAndExit(name string) {
	elf, err := os.ReadFile("testdata/" + name)
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
	// for a well-formed static-PIE that calls exit_group).
	// Exit cleanly so the outer test sees exit 0.
	os.Exit(0)
}
