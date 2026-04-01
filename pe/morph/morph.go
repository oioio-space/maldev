// Package morph provides UPX header mutation for PE files.
package morph

import (
	"math/rand"
	"strings"

	"github.com/saferwall/pe"
)

// Go 1.20+ auto-seeds the global rand source; no init() needed.

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

// UPXMorph replaces the UPX signature in a packed PE with random bytes
// to prevent automatic unpacking and change the file hash.
// If the file is not UPX-packed, the data is returned unchanged.
func UPXMorph(peData []byte) ([]byte, error) {
	pefile, err := pe.NewBytes(peData, &pe.Options{Fast: true})
	if err != nil {
		return peData, err
	}
	defer pefile.Close()

	err = pefile.Parse()
	if err != nil {
		return peData, err
	}

	for _, section := range pefile.Sections {
		if strings.Contains(section.String(), "UPX1") {
			offset := section.Header.PointerToRawData
			copy(peData[offset:], []byte(randomString(8)))
			break
		}
	}

	return peData, nil
}

// UPXFix restores the original UPX signature in a packed PE file.
func UPXFix(peData []byte) ([]byte, error) {
	pefile, err := pe.NewBytes(peData, &pe.Options{Fast: true})
	if err != nil {
		return peData, err
	}
	defer pefile.Close()

	err = pefile.Parse()
	if err != nil {
		return peData, err
	}

	for _, section := range pefile.Sections {
		if strings.Contains(section.String(), "UPX1") {
			offset := section.Header.PointerToRawData
			copy(peData[offset:], []byte("3.96.UPX"))
			break
		}
	}

	return peData, nil
}
