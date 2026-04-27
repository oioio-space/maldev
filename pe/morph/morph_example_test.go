package morph_test

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/pe/morph"
)

// UPXMorph replaces the literal "UPX!" signature inside section
// headers and l_info with random non-zero bytes, breaking
// off-the-shelf static unpackers while preserving the runtime
// stub.
func ExampleUPXMorph() {
	raw, err := os.ReadFile("payload.upx.exe")
	if err != nil {
		return
	}
	morphed, err := morph.UPXMorph(raw)
	if err != nil {
		return
	}
	fmt.Printf("morphed %d bytes\n", len(morphed))
	_ = os.WriteFile("payload.morph.exe", morphed, 0o644)
}
