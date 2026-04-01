// Package morph provides UPX header mutation for PE files.
package morph

import (
	"strings"

	"github.com/oioio-space/maldev/core/utils"
	"github.com/saferwall/pe"
)

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
			s, _ := utils.RandomString(8)
			copy(peData[offset:], []byte(s))
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
