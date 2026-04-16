// Standalone validation binary: imports masquerade/cmd and exits.
// Used only for the E2E test that reads VERSIONINFO of the output PE.

package main

import (
	_ "github.com/oioio-space/maldev/pe/masquerade/preset/cmd"
)

func main() {}
