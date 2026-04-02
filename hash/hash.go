package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

func MD5(data []byte) string    { return fmt.Sprintf("%x", md5.Sum(data)) }
func SHA1(data []byte) string   { h := sha1.Sum(data); return fmt.Sprintf("%x", h) }
func SHA256(data []byte) string { h := sha256.Sum256(data); return fmt.Sprintf("%x", h) }
func SHA512(data []byte) string { h := sha512.Sum512(data); return fmt.Sprintf("%x", h) }
