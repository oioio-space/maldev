package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// MD5 returns the MD5 digest of data as a lowercase hex string.
func MD5(data []byte) string { return fmt.Sprintf("%x", md5.Sum(data)) }

// SHA1 returns the SHA-1 digest of data as a lowercase hex string.
func SHA1(data []byte) string { h := sha1.Sum(data); return fmt.Sprintf("%x", h) }

// SHA256 returns the SHA-256 digest of data as a lowercase hex string.
func SHA256(data []byte) string { h := sha256.Sum256(data); return fmt.Sprintf("%x", h) }

// SHA512 returns the SHA-512 digest of data as a lowercase hex string.
func SHA512(data []byte) string { h := sha512.Sum512(data); return fmt.Sprintf("%x", h) }
