package samdump

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// User enumeration + V-value parsing.
//
// SAM users live under `SAM\Domains\Account\Users\<RID-hex>`. Each
// RID subkey carries:
//
//   - F: fixed-size USER_F (~0x40 bytes) — UserAccountControl, last
//     logon timestamps, account flags. We don't need most of it.
//   - V: variable-size USER_V starting with a 0xCC-byte offset table
//     of (Offset uint32, Length uint32, _ uint32) triples pointing
//     into the variable payload that follows. Username,
//     NT-hash-blob, LM-hash-blob, and many other strings all live
//     in the payload.
//
// Each Offset is relative to the END of the 0xCC header (i.e., to
// the variable payload start).

// ErrUserParse fires when a user record fails structural validation
// (V value too short, offset/length out of bounds, malformed
// username encoding).
var ErrUserParse = errors.New("samdump: user record parse failed")

// usersPath is the SAM hive path under which per-RID subkeys live.
const usersPath = `SAM\Domains\Account\Users`

// accountPath is the parent of Users that carries the F value with
// the SAM_KEY_DATA_AES / legacy SAM_KEY needed for the domain
// hashed-bootkey derivation.
const accountPath = `SAM\Domains\Account`

// userVHeaderSize is the fixed-size offset table at the start of
// every V value. Stable across every NT release that uses the SAM
// hive (NT 3.x → Win 11 25H2).
const userVHeaderSize = 0xCC

// Field positions inside the userVHeaderSize bytes — sourced from
// impacket secretsdump.py USER_V structure. Each field is a 4-byte
// uint32 (offset relative to header end) followed by a 4-byte length
// followed by 4 bytes of padding/unused.
const (
	userVOffName     = 0x0C
	userVLenName     = 0x10
	userVOffLMHash   = 0x9C
	userVLenLMHash   = 0xA0
	userVOffNTHash   = 0xA8
	userVLenNTHash   = 0xAC
)

// Fixed positions inside the per-user F value (USER_F). impacket's
// `USER_F` puts UserID at offset 0x30. We don't currently consume
// the other F fields.
const (
	userFOffUserID = 0x30
)

// listUserRIDs returns the parsed RIDs of every subkey under
// `SAM\Domains\Account\Users`. Subkeys whose name doesn't decode as
// 8-char hex (the "Names" mapping subkey + any other auxiliary
// entries) are skipped silently.
func listUserRIDs(sam *hive) ([]uint32, error) {
	users, err := sam.openPath(usersPath)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrUserParse, usersPath, err)
	}
	if users.SubkeyCount == 0 || users.SubkeyListOff <= 0 {
		return nil, nil
	}
	offsets, err := sam.expandSubkeyList(users.SubkeyListOff)
	if err != nil {
		return nil, fmt.Errorf("%w: expand Users subkey list: %v", ErrUserParse, err)
	}
	out := make([]uint32, 0, len(offsets))
	for _, off := range offsets {
		nk, err := sam.openCellNK(off)
		if err != nil {
			continue
		}
		// Subkey names are 8-char hex (e.g. "000001F4" = RID 500).
		// Anything else (the "Names" auxiliary subkey, custom
		// extensions) is skipped.
		if len(nk.Name) != 8 {
			continue
		}
		rid, err := strconv.ParseUint(nk.Name, 16, 32)
		if err != nil {
			continue
		}
		out = append(out, uint32(rid))
	}
	return out, nil
}

// readUserV returns the raw V value bytes for the given RID.
func readUserV(sam *hive, rid uint32) ([]byte, error) {
	name := fmt.Sprintf("%08X", rid)
	users, err := sam.openPath(usersPath)
	if err != nil {
		return nil, fmt.Errorf("%w: open Users: %v", ErrUserParse, err)
	}
	user, err := sam.openSubkey(users, name)
	if err != nil {
		return nil, fmt.Errorf("%w: open user %s: %v", ErrUserParse, name, err)
	}
	v, _, err := sam.readValue(user, "V")
	if err != nil {
		return nil, fmt.Errorf("%w: read V of %s: %v", ErrUserParse, name, err)
	}
	return v, nil
}

// parsedUserV carries the fields the SAM-dump algorithm consumes
// from a single V value. Empty fields are zero-length but never nil.
type parsedUserV struct {
	Username  string
	NTHashEnc []byte
	LMHashEnc []byte
}

// parseUserV decodes the offset table at the start of v and pulls
// out the username + NT/LM encrypted-hash blobs. Returns ErrUserParse
// for any structural anomaly.
func parseUserV(v []byte) (parsedUserV, error) {
	if len(v) < userVHeaderSize {
		return parsedUserV{}, fmt.Errorf("%w: V value shorter than header (%d < %d)",
			ErrUserParse, len(v), userVHeaderSize)
	}
	payloadStart := userVHeaderSize
	payload := v[payloadStart:]

	pickSlice := func(offField, lenField int) ([]byte, error) {
		off := binary.LittleEndian.Uint32(v[offField : offField+4])
		l := binary.LittleEndian.Uint32(v[lenField : lenField+4])
		if l == 0 {
			return nil, nil
		}
		if uint64(off)+uint64(l) > uint64(len(payload)) {
			return nil, fmt.Errorf("%w: field [off=0x%X len=%d] overruns payload (len=%d)",
				ErrUserParse, off, l, len(payload))
		}
		out := make([]byte, l)
		copy(out, payload[off:off+l])
		return out, nil
	}

	nameBytes, err := pickSlice(userVOffName, userVLenName)
	if err != nil {
		return parsedUserV{}, fmt.Errorf("name: %w", err)
	}
	ntBytes, err := pickSlice(userVOffNTHash, userVLenNTHash)
	if err != nil {
		return parsedUserV{}, fmt.Errorf("nthash: %w", err)
	}
	lmBytes, err := pickSlice(userVOffLMHash, userVLenLMHash)
	if err != nil {
		return parsedUserV{}, fmt.Errorf("lmhash: %w", err)
	}

	out := parsedUserV{
		Username:  utf16BytesToString(nameBytes),
		NTHashEnc: ntBytes,
		LMHashEnc: lmBytes,
	}
	out.Username = strings.TrimRight(out.Username, "\x00")
	return out, nil
}

// readDomainAccountF returns the SAM\Domains\Account\F bytes the
// domain-hashed-bootkey derivation needs.
func readDomainAccountF(sam *hive) ([]byte, error) {
	acct, err := sam.openPath(accountPath)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrUserParse, accountPath, err)
	}
	f, _, err := sam.readValue(acct, "F")
	if err != nil {
		return nil, fmt.Errorf("%w: read F: %v", ErrUserParse, err)
	}
	return f, nil
}
