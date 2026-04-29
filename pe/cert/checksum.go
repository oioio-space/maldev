package cert

import (
	"encoding/binary"
)

// peChecksumOffset returns the byte offset of the
// IMAGE_OPTIONAL_HEADER.CheckSum field. The offset (64 bytes into the
// optional header) is identical for PE32 and PE32+ — only the
// preceding fields differ in width, summing to the same total.
func peChecksumOffset(data []byte) (int, error) {
	if len(data) < 0x40 {
		return 0, ErrInvalidPE
	}
	lfanew := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if lfanew < 0 || lfanew+4+20+64+4 > len(data) {
		return 0, ErrInvalidPE
	}
	if string(data[lfanew:lfanew+4]) != "PE\x00\x00" {
		return 0, ErrInvalidPE
	}
	return lfanew + 4 + 20 + 64, nil
}

// computePECheckSum implements the PE-image checksum from
// IMAGE_OPTIONAL_HEADER — the same algorithm ImageHlp!CheckSumMappedFile
// produces: sum 16-bit words with rolling 16-bit carry, treat the
// 4-byte CheckSum field as zero, then add the file size.
//
// checksumOffset is masked to zero so the result is independent of
// whatever value already sits in the header.
func computePECheckSum(data []byte, checksumOffset int) uint32 {
	var sum uint32
	n := len(data)
	end := n &^ 1 // largest even index
	for i := 0; i < end; i += 2 {
		if i == checksumOffset || i == checksumOffset+2 {
			continue
		}
		sum += uint32(binary.LittleEndian.Uint16(data[i : i+2]))
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	if n&1 == 1 {
		sum += uint32(data[n-1])
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return sum + uint32(n)
}

// PatchPECheckSum recomputes IMAGE_OPTIONAL_HEADER.CheckSum and
// writes it back into data in place. Use after any splice that
// changes the byte content of a PE you want to keep verifiable
// against ImageHlp!CheckSumMappedFile (Authenticode signing tools,
// some EDRs, the Windows loader for kernel-mode images).
//
// Returns [ErrInvalidPE] if data is too short or the PE header is
// missing.
func PatchPECheckSum(data []byte) error {
	off, err := peChecksumOffset(data)
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(data[off:off+4], 0)
	sum := computePECheckSum(data, off)
	binary.LittleEndian.PutUint32(data[off:off+4], sum)
	return nil
}
