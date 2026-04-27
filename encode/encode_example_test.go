package encode_test

import (
	"fmt"

	"github.com/oioio-space/maldev/encode"
)

// Base64 round-trip — RFC 4648 §4 (standard alphabet).
func ExampleBase64Encode() {
	encoded := encode.Base64Encode([]byte("hello"))
	decoded, _ := encode.Base64Decode(encoded)
	fmt.Println(string(decoded))
	// Output: hello
}

// Base64URL — same data with URL-safe alphabet (no `+` or `/`).
func ExampleBase64URLEncode() {
	encoded := encode.Base64URLEncode([]byte{0xff, 0xfe, 0xfd})
	fmt.Println(encoded)
	// Output: __79
}

// PowerShell `-EncodedCommand` format = Base64(UTF-16LE(script)).
// Drop the result into `powershell.exe -EncodedCommand <output>`.
func ExamplePowerShell() {
	encoded := encode.PowerShell("Get-Process")
	fmt.Println(encoded)
	// Output: RwBlAHQALQBQAHIAbwBjAGUAcwBzAA==
}

// UTF-16LE for direct use as a Windows API string parameter.
func ExampleToUTF16LE() {
	bytes := encode.ToUTF16LE("AB")
	fmt.Printf("% x\n", bytes)
	// Output: 41 00 42 00
}
