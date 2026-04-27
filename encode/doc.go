// Package encode provides encoding / decoding utilities for payload
// transformation: Base64 (standard + URL-safe), UTF-16LE (Windows API
// strings), ROT13, and PowerShell `-EncodedCommand` format.
//
// Pure functions, no side effects. Cross-platform.
//
//   - `Base64Encode` / `Base64Decode` — RFC 4648 §4 standard encoding.
//   - `Base64URLEncode` / `Base64URLDecode` — RFC 4648 §5 URL-safe.
//   - `ToUTF16LE` — Go `string` → little-endian UTF-16 bytes (the
//     format Windows API parameters expect).
//   - `ROT13` — Caesar shift by 13 over ASCII letters; non-alpha
//     bytes pass through.
//   - `PowerShell` — `Base64(UTF-16LE(script))`, the format
//     `powershell.exe -EncodedCommand` accepts.
//
// # MITRE ATT&CK
//
//   - T1027 (Obfuscated Files or Information) — for the PowerShell
//     encoded-command and Base64 wrappers
//
// # Detection level
//
// very-quiet
//
// Pure data transforms. No system interaction.
//
// # Example
//
// See [ExampleBase64Encode] and [ExamplePowerShell] in
// encode_example_test.go.
//
// # See also
//
//   - docs/techniques/encode/README.md
//   - [github.com/oioio-space/maldev/crypto] — encryption layer
//
// [github.com/oioio-space/maldev/crypto]: https://pkg.go.dev/github.com/oioio-space/maldev/crypto
package encode
