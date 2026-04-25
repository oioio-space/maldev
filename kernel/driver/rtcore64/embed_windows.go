//go:build windows && !byovd_rtcore64

package rtcore64

// loadDriverBytes returns the embedded RTCore64.sys bytes. The default
// build-tag-less variant ships no driver — callers must build with
// -tags=byovd_rtcore64 and provide the binary in a sibling
// embed_byovd_rtcore64_windows.go that overrides this symbol.
//
// Why split: the open-source repo declines to redistribute MSI's signed
// binary (licensing) and Microsoft's vulnerable-driver block list flags
// it as malicious — shipping it by default would trip every CI scanner.
func loadDriverBytes() ([]byte, error) {
	return nil, ErrDriverBytesMissing
}
