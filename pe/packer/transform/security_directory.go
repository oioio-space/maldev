package transform

import (
	"encoding/binary"
	"fmt"
)

// dirSecurity is the DataDirectory index for the Authenticode
// certificate table (IMAGE_DIRECTORY_ENTRY_SECURITY). Quirk: the
// VirtualAddress field for THIS directory is a FILE OFFSET, not
// an RVA — `WIN_CERTIFICATE` blobs live outside any section,
// typically at the end of the file.
const dirSecurity = 4

// StripPESecurityDirectory zeroes out DataDirectory[SECURITY] so
// the packed output appears UNSIGNED rather than
// SIGNED-BUT-TAMPERED.
//
// PackBinary's `.text` mutation invalidates any Authenticode
// signature regardless — once the hashed code section bytes
// change, the PKCS#7 SignedData blob no longer matches and any
// signature check (sigcheck.exe, AppLocker, WDAC) will report
// the file as tampered. That's a much louder OPSEC signal than
// a clean "unsigned" file.
//
// On top of the integrity break, `InjectStubPE` appends the
// stub section past the existing sections' file extent — which
// often lands inside or past the cert region, partially or
// fully overwriting the WIN_CERTIFICATE bytes. Zeroing the
// directory entry decouples the operator from that race: the
// packed file simply doesn't claim to carry a cert.
//
// The cert bytes themselves may still sit in the file (we
// don't truncate); only the directory pointer is zeroed.
// Tools that scan raw file bytes for cert markers may still
// false-positive, but Windows + every standard signature
// checker reads via DataDirectory and now sees no cert.
//
// Returns nil when the directory entry was already zero
// (no-op). Mutates `pe` in place.
func StripPESecurityDirectory(pe []byte) error {
	l, err := parsePELayout(pe)
	if err != nil {
		return err
	}
	dirEntryOff := l.optOff + OptDataDirsStart + dirSecurity*OptDataDirEntrySize
	if int(dirEntryOff)+OptDataDirEntrySize > len(pe) {
		return fmt.Errorf("transform: PE too short for SECURITY DataDirectory")
	}
	binary.LittleEndian.PutUint32(pe[dirEntryOff:], 0)
	binary.LittleEndian.PutUint32(pe[dirEntryOff+4:], 0)
	return nil
}
