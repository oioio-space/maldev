package lsasparse

import (
	"encoding/binary"
	"fmt"
)

// DPAPILayout captures per-build offsets inside a
// KIWI_MASTERKEY_CACHE_ENTRY node. Field offsets are byte distances
// from the start of the node.
//
// Set NodeSize=0 (zero value) and the DPAPI walker is skipped — a
// template that lacks DPAPI support stays inert without runtime
// cost.
type DPAPILayout struct {
	NodeSize uint32

	// LUID — locally-unique session id. Used to merge a master-key
	// credential into the matching MSV1_0 LogonSession by LUID.
	LUIDOffset uint32

	// KeyGUIDOffset is the offset to the 16-byte GUID identifying
	// the master key. The DPAPI client (Chrome, Outlook, Vault, …)
	// looks up master keys by this GUID when decrypting blobs.
	KeyGUIDOffset uint32

	// KeySizeOffset is the offset to a uint32 holding the inline-key
	// length. Typical Win10 entries store 64-byte keys (SHA1-derived)
	// but the field is variable — readers must trust the size value.
	KeySizeOffset uint32

	// KeyBytesOffset is the offset where the inline key payload
	// begins. The walker reads KeySize bytes starting here.
	KeyBytesOffset uint32
}

// DPAPIMasterKey is one decrypted-in-cache master key extracted
// from lsasrv.dll's g_MasterKeyCacheList.
//
// KeyBytes is the value Microsoft caches AFTER the per-session
// password-derived decryption — the same bytes the DPAPI client
// would feed to BCryptDecrypt to unwrap a downstream blob (Chrome
// cookies, Vault credentials, WinRM saved sessions, …). Treat these
// bytes as the most sensitive payload Result.Wipe can clear.
//
// Format the GUID via DPAPIMasterKey.GUIDString() — Microsoft uses
// the standard 8-4-4-4-12 hyphenated form (e.g.,
// "9CC0C2D9-89A6-4B4A-8B11-7B0F0E1234AB") with little-endian for
// the first three components, big-endian for the last two.
type DPAPIMasterKey struct {
	LUID     uint64
	KeyGUID  [16]byte
	KeyBytes []byte
	Found    bool
}

// AuthPackage satisfies the Credential interface. DPAPI itself is
// not an auth package in the LSA sense, but the Credential
// abstraction is "named credential payload" — "DPAPI" matches what
// pypykatz emits in its JSON output.
func (DPAPIMasterKey) AuthPackage() string { return "DPAPI" }

// String renders one line per master key: GUID:hex-key. Suitable for
// logging or as input to a downstream blob decryptor that expects
// `{<GUID>}:<hex>` format.
func (k DPAPIMasterKey) String() string {
	return fmt.Sprintf("{%s}:%s", k.GUIDString(), hexLower(k.KeyBytes))
}

// GUIDString formats the 16-byte GUID as the canonical Microsoft
// 8-4-4-4-12 hyphenated string. The first three components are
// little-endian (data1, data2, data3); the last two are
// byte-for-byte (data4 + node).
func (k DPAPIMasterKey) GUIDString() string {
	g := k.KeyGUID
	d1 := binary.LittleEndian.Uint32(g[0:4])
	d2 := binary.LittleEndian.Uint16(g[4:6])
	d3 := binary.LittleEndian.Uint16(g[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3,
		g[8], g[9],
		g[10], g[11], g[12], g[13], g[14], g[15],
	)
}

// wipe satisfies the optional wipe interface that Result.Wipe calls.
// Master-key bytes are higher-value than NT hashes (decryption key
// for downstream blobs) — wipe them on Result.Wipe.
func (k *DPAPIMasterKey) wipe() {
	for i := range k.KeyBytes {
		k.KeyBytes[i] = 0
	}
	k.KeyBytes = nil
	for i := range k.KeyGUID {
		k.KeyGUID[i] = 0
	}
	k.Found = false
}

// extractDPAPI walks lsasrv.dll's g_MasterKeyCacheList and returns
// every master-key cache entry, keyed by LUID for cheap merge with
// MSV LogonSessions.
//
// Returns (nil, nil) without warning when the template lacks DPAPI
// support (DPAPILayout.NodeSize == 0) — the zero-value default for
// templates that haven't been extended.
//
// The cached key bytes are already decrypted; we don't go through
// decryptLSA. Future work can add a "MasterKey blob still encrypted"
// path for the rare LCUs where the cache holds ciphertext, but every
// Win10/Win11 path observed today caches plaintext.
func extractDPAPI(r *reader, lsasrv Module, t *Template) (map[uint64]DPAPIMasterKey, []string) {
	if t.DPAPILayout.NodeSize == 0 || len(t.DPAPIListPattern) == 0 {
		return nil, nil
	}

	body, err := r.ReadVA(lsasrv.BaseOfImage, int(lsasrv.SizeOfImage))
	if err != nil {
		return nil, []string{fmt.Sprintf("DPAPI: read lsasrv.dll body: %v", err)}
	}

	listHead, err := derefRel32(
		body,
		lsasrv.BaseOfImage,
		t.DPAPIListPattern,
		t.DPAPIListWildcards,
		t.DPAPIListOffset,
		r,
	)
	if err != nil {
		return nil, []string{fmt.Sprintf("DPAPI list head: %v", err)}
	}

	flink, err := readPointer(r, listHead)
	if err != nil || flink == 0 || flink == listHead {
		return nil, nil
	}

	keys := make(map[uint64]DPAPIMasterKey)
	var warnings []string

	const maxNodes = 1024
	walked := 0
	for cur := flink; cur != listHead && walked < maxNodes; walked++ {
		node, err := r.ReadVA(cur, int(t.DPAPILayout.NodeSize))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("DPAPI node @0x%X: %v", cur, err))
			break
		}
		if mk, warn := decodeDPAPINode(node, t.DPAPILayout); warn != "" {
			warnings = append(warnings, warn)
		} else if mk.Found {
			keys[mk.LUID] = mk
		}
		next, err := readPointer(r, cur) // Flink at offset 0
		if err != nil || next == 0 {
			break
		}
		cur = next
	}

	return keys, warnings
}

// decodeDPAPINode projects a node-bytes blob through the layout to a
// DPAPIMasterKey. The key bytes are inlined past KeyBytesOffset for
// KeySize bytes; we copy them so the returned slice survives a
// later reader buffer reuse.
func decodeDPAPINode(node []byte, l DPAPILayout) (DPAPIMasterKey, string) {
	if uint32(len(node)) < l.NodeSize {
		return DPAPIMasterKey{}, fmt.Sprintf("DPAPI node too small: %d < %d", len(node), l.NodeSize)
	}

	luid := binary.LittleEndian.Uint64(node[l.LUIDOffset : l.LUIDOffset+8])

	var guid [16]byte
	copy(guid[:], node[l.KeyGUIDOffset:l.KeyGUIDOffset+16])

	keySize := binary.LittleEndian.Uint32(node[l.KeySizeOffset : l.KeySizeOffset+4])
	if keySize == 0 || keySize > 1024 {
		// 1KB cap defeats malformed dumps where a stray pointer
		// landed in the size field. Real Win10 entries are 64 bytes;
		// no legitimate DPAPI cache key reaches a kilobyte.
		return DPAPIMasterKey{LUID: luid, KeyGUID: guid}, ""
	}
	if l.KeyBytesOffset+keySize > l.NodeSize {
		return DPAPIMasterKey{}, fmt.Sprintf("DPAPI key size %d overruns node size %d", keySize, l.NodeSize)
	}
	keyBytes := make([]byte, keySize)
	copy(keyBytes, node[l.KeyBytesOffset:l.KeyBytesOffset+keySize])

	return DPAPIMasterKey{
		LUID:     luid,
		KeyGUID:  guid,
		KeyBytes: keyBytes,
		Found:    !isAllZero(keyBytes),
	}, ""
}

// mergeDPAPI grafts master keys onto matching MSV LogonSession
// entries by LUID. The Credentials slice already holds MSV1_0 +
// optional Wdigest entries — DPAPI master keys join the same slice
// so callers iterate one collection.
//
// LUIDs with no MSV match surface as new sessions carrying only the
// DPAPIMasterKey credential; mirrors mergeWdigest's orphan handling
// so no extracted secret is silently dropped.
func mergeDPAPI(sessions []LogonSession, keys map[uint64]DPAPIMasterKey) []LogonSession {
	if len(keys) == 0 {
		return sessions
	}
	seen := make(map[uint64]bool, len(sessions))
	for i := range sessions {
		if k, ok := keys[sessions[i].LUID]; ok {
			sessions[i].Credentials = append(sessions[i].Credentials, k)
			seen[sessions[i].LUID] = true
		}
	}
	for luid, k := range keys {
		if seen[luid] {
			continue
		}
		sessions = append(sessions, LogonSession{
			LUID:        luid,
			Credentials: []Credential{k},
		})
	}
	return sessions
}

// hexLower writes b as a lowercase hex string. Local helper to avoid
// adding encoding/hex to this file's imports — every caller already
// pulls encoding/binary which is enough.
func hexLower(b []byte) string {
	const tab = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = tab[c>>4]
		out[i*2+1] = tab[c&0x0F]
	}
	return string(out)
}
