package encode

import (
	"encoding/base64"
	"unicode/utf16"
)

func Base64Encode(data []byte) string  { return base64.StdEncoding.EncodeToString(data) }
func Base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
func Base64URLEncode(data []byte) string         { return base64.URLEncoding.EncodeToString(data) }
func Base64URLDecode(data string) ([]byte, error) { return base64.URLEncoding.DecodeString(data) }

func ToUTF16LE(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	b := make([]byte, len(encoded)*2)
	for i, r := range encoded {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return b
}

func PowerShell(script string) string {
	return base64.StdEncoding.EncodeToString(ToUTF16LE(script))
}

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
