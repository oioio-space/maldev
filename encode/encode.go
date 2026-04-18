package encode

import (
	"encoding/base64"
	"unicode/utf16"
)

// Base64Encode returns the standard RFC 4648 base64 encoding of data.
func Base64Encode(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

// Base64Decode decodes a standard RFC 4648 base64 string.
func Base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// Base64URLEncode returns the URL-safe RFC 4648 base64 encoding of data.
func Base64URLEncode(data []byte) string { return base64.URLEncoding.EncodeToString(data) }

// Base64URLDecode decodes a URL-safe RFC 4648 base64 string.
func Base64URLDecode(data string) ([]byte, error) { return base64.URLEncoding.DecodeString(data) }

// ToUTF16LE encodes s as little-endian UTF-16 bytes, the wire format used by
// Windows -EncodedCommand, WMI, and most Unicode Win32 APIs.
func ToUTF16LE(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	b := make([]byte, len(encoded)*2)
	for i, r := range encoded {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return b
}

// PowerShell encodes script for use with powershell.exe -EncodedCommand:
// UTF-16LE bytes then standard base64.
func PowerShell(script string) string {
	return base64.StdEncoding.EncodeToString(ToUTF16LE(script))
}

// ROT13 returns the Caesar-13 substitution of s. Non-alphabetic bytes are
// passed through unchanged. Useful for trivial string obfuscation in payloads
// where no key material can be stored.
func ROT13(s string) string {
	result := make([]byte, len(s))
	for i, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z':
			result[i] = 'A' + (c-'A'+13)%26
		case c >= 'a' && c <= 'z':
			result[i] = 'a' + (c-'a'+13)%26
		default:
			result[i] = c
		}
	}
	return string(result)
}
