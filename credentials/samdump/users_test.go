package samdump

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// fixtureUserV builds a synthetic V value with username + NT + LM
// blobs at the canonical offsets. The header zeros every field we
// don't populate; the payload is concatenated as
// (name || nt || lm). Each Offset/Length pair points at the right
// payload slice.
func fixtureUserV(name string, ntBlob, lmBlob []byte) []byte {
	utf16Name := make([]byte, 0, len(name)*2)
	for _, c := range name {
		var enc [2]byte
		binary.LittleEndian.PutUint16(enc[:], uint16(c))
		utf16Name = append(utf16Name, enc[:]...)
	}
	payload := make([]byte, 0, len(utf16Name)+len(ntBlob)+len(lmBlob))
	payload = append(payload, utf16Name...)
	nameOff := uint32(0)
	nameLen := uint32(len(utf16Name))
	payload = append(payload, lmBlob...)
	lmOff := nameLen
	lmLen := uint32(len(lmBlob))
	payload = append(payload, ntBlob...)
	ntOff := lmOff + lmLen
	ntLen := uint32(len(ntBlob))

	v := make([]byte, userVHeaderSize+len(payload))
	binary.LittleEndian.PutUint32(v[userVOffName:userVOffName+4], nameOff)
	binary.LittleEndian.PutUint32(v[userVLenName:userVLenName+4], nameLen)
	binary.LittleEndian.PutUint32(v[userVOffLMHash:userVOffLMHash+4], lmOff)
	binary.LittleEndian.PutUint32(v[userVLenLMHash:userVLenLMHash+4], lmLen)
	binary.LittleEndian.PutUint32(v[userVOffNTHash:userVOffNTHash+4], ntOff)
	binary.LittleEndian.PutUint32(v[userVLenNTHash:userVLenNTHash+4], ntLen)
	copy(v[userVHeaderSize:], payload)
	return v
}

func TestParseUserV_ExtractsName(t *testing.T) {
	v := fixtureUserV("Administrator", nil, nil)
	got, err := parseUserV(v)
	if err != nil {
		t.Fatalf("parseUserV: %v", err)
	}
	if got.Username != "Administrator" {
		t.Errorf("Username = %q, want %q", got.Username, "Administrator")
	}
}

func TestParseUserV_ExtractsHashBlobs(t *testing.T) {
	nt := bytes.Repeat([]byte{0xAA}, 20) // legacy NT blob (header+cipher)
	lm := bytes.Repeat([]byte{0xBB}, 20)
	v := fixtureUserV("alice", nt, lm)
	got, err := parseUserV(v)
	if err != nil {
		t.Fatalf("parseUserV: %v", err)
	}
	if !bytes.Equal(got.NTHashEnc, nt) {
		t.Errorf("NTHashEnc:\n  got  % X\n  want % X", got.NTHashEnc, nt)
	}
	if !bytes.Equal(got.LMHashEnc, lm) {
		t.Errorf("LMHashEnc:\n  got  % X\n  want % X", got.LMHashEnc, lm)
	}
}

func TestParseUserV_RejectsTooShort(t *testing.T) {
	_, err := parseUserV(make([]byte, userVHeaderSize-1))
	if !errors.Is(err, ErrUserParse) {
		t.Fatalf("err = %v, want wrap of ErrUserParse", err)
	}
}

func TestParseUserV_RejectsOverrunOffset(t *testing.T) {
	v := make([]byte, userVHeaderSize+8)
	// Set name offset+length so it overruns the 8-byte payload.
	binary.LittleEndian.PutUint32(v[userVOffName:userVOffName+4], 0)
	binary.LittleEndian.PutUint32(v[userVLenName:userVLenName+4], 99)
	_, err := parseUserV(v)
	if !errors.Is(err, ErrUserParse) {
		t.Fatalf("err = %v, want wrap of ErrUserParse", err)
	}
}

func TestParseUserV_StripsTrailingNul(t *testing.T) {
	// Construct a name with trailing NUL UTF-16 character.
	v := fixtureUserV("guest\x00", nil, nil)
	got, err := parseUserV(v)
	if err != nil {
		t.Fatalf("parseUserV: %v", err)
	}
	if strings.HasSuffix(got.Username, "\x00") {
		t.Errorf("Username %q still has trailing NUL", got.Username)
	}
	if got.Username != "guest" {
		t.Errorf("Username = %q, want %q", got.Username, "guest")
	}
}

func TestParseUserV_EmptyHashLengthsReturnNil(t *testing.T) {
	v := fixtureUserV("svc", nil, nil)
	got, err := parseUserV(v)
	if err != nil {
		t.Fatalf("parseUserV: %v", err)
	}
	if got.NTHashEnc != nil {
		t.Errorf("NTHashEnc = % X, want nil for length-0 slot", got.NTHashEnc)
	}
	if got.LMHashEnc != nil {
		t.Errorf("LMHashEnc = % X, want nil for length-0 slot", got.LMHashEnc)
	}
	// History slots default to empty too — verify they don't smuggle
	// in stray bytes when the caller didn't populate them.
	if got.NTHistoryEnc != nil {
		t.Errorf("NTHistoryEnc = % X, want nil for length-0 slot", got.NTHistoryEnc)
	}
	if got.LMHistoryEnc != nil {
		t.Errorf("LMHistoryEnc = % X, want nil for length-0 slot", got.LMHistoryEnc)
	}
}

// fixtureUserVWithHistory extends fixtureUserV with the two
// password-history blobs at their canonical offsets. Layout in the
// payload section: name || LM || NT || NTHist || LMHist.
func fixtureUserVWithHistory(name string, ntBlob, lmBlob, ntHistBlob, lmHistBlob []byte) []byte {
	utf16Name := make([]byte, 0, len(name)*2)
	for _, c := range name {
		var enc [2]byte
		binary.LittleEndian.PutUint16(enc[:], uint16(c))
		utf16Name = append(utf16Name, enc[:]...)
	}

	payload := make([]byte, 0,
		len(utf16Name)+len(lmBlob)+len(ntBlob)+len(ntHistBlob)+len(lmHistBlob))
	payload = append(payload, utf16Name...)
	nameOff := uint32(0)
	nameLen := uint32(len(utf16Name))

	payload = append(payload, lmBlob...)
	lmOff := nameLen
	lmLen := uint32(len(lmBlob))

	payload = append(payload, ntBlob...)
	ntOff := lmOff + lmLen
	ntLen := uint32(len(ntBlob))

	payload = append(payload, ntHistBlob...)
	ntHistOff := ntOff + ntLen
	ntHistLen := uint32(len(ntHistBlob))

	payload = append(payload, lmHistBlob...)
	lmHistOff := ntHistOff + ntHistLen
	lmHistLen := uint32(len(lmHistBlob))

	v := make([]byte, userVHeaderSize+len(payload))
	binary.LittleEndian.PutUint32(v[userVOffName:userVOffName+4], nameOff)
	binary.LittleEndian.PutUint32(v[userVLenName:userVLenName+4], nameLen)
	binary.LittleEndian.PutUint32(v[userVOffLMHash:userVOffLMHash+4], lmOff)
	binary.LittleEndian.PutUint32(v[userVLenLMHash:userVLenLMHash+4], lmLen)
	binary.LittleEndian.PutUint32(v[userVOffNTHash:userVOffNTHash+4], ntOff)
	binary.LittleEndian.PutUint32(v[userVLenNTHash:userVLenNTHash+4], ntLen)
	binary.LittleEndian.PutUint32(v[userVOffNTHistory:userVOffNTHistory+4], ntHistOff)
	binary.LittleEndian.PutUint32(v[userVLenNTHistory:userVLenNTHistory+4], ntHistLen)
	binary.LittleEndian.PutUint32(v[userVOffLMHistory:userVOffLMHistory+4], lmHistOff)
	binary.LittleEndian.PutUint32(v[userVLenLMHistory:userVLenLMHistory+4], lmHistLen)
	copy(v[userVHeaderSize:], payload)
	return v
}

func TestParseUserV_ExtractsHistoryBlobs(t *testing.T) {
	nt := bytes.Repeat([]byte{0xAA}, 20)
	lm := bytes.Repeat([]byte{0xBB}, 20)
	ntHist := bytes.Repeat([]byte{0xCC}, 36) // 4-byte SAM_HASH header + 2×16
	lmHist := bytes.Repeat([]byte{0xDD}, 20) // 4-byte SAM_HASH header + 1×16
	v := fixtureUserVWithHistory("alice", nt, lm, ntHist, lmHist)
	got, err := parseUserV(v)
	if err != nil {
		t.Fatalf("parseUserV: %v", err)
	}
	if !bytes.Equal(got.NTHistoryEnc, ntHist) {
		t.Errorf("NTHistoryEnc:\n  got  % X\n  want % X", got.NTHistoryEnc, ntHist)
	}
	if !bytes.Equal(got.LMHistoryEnc, lmHist) {
		t.Errorf("LMHistoryEnc:\n  got  % X\n  want % X", got.LMHistoryEnc, lmHist)
	}
}

func TestParseUserV_RejectsOverrunHistoryOffset(t *testing.T) {
	v := make([]byte, userVHeaderSize+8)
	// Plant an out-of-range NT-history offset/length pair to trip the
	// payload-bounds check.
	binary.LittleEndian.PutUint32(v[userVOffNTHistory:userVOffNTHistory+4], 0)
	binary.LittleEndian.PutUint32(v[userVLenNTHistory:userVLenNTHistory+4], 99)
	_, err := parseUserV(v)
	if !errors.Is(err, ErrUserParse) {
		t.Fatalf("err = %v, want wrap of ErrUserParse for overrunning NTHistory length", err)
	}
}
