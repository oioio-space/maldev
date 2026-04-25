package sekurlsa

import (
	"encoding/binary"
	"fmt"
)

// KerberosLayout captures every offset the Kerberos walker needs to
// project a KIWI_KERBEROS_LOGON_SESSION node + its three ticket
// caches. Set NodeSize=0 to disable.
//
// Two structural anchors live at fixed offsets across every Vista+
// build (KvcForensic + pypykatz agree):
//
//   - KIWI_KERBEROS_EXTERNAL_NAME at +0x00 NameType (u32) +
//     +0x04 NameCount (u32) + +0x08 first UNICODE_STRING (16 bytes).
//   - The walker hardcodes those — no Layout field exposed.
type KerberosLayout struct {
	NodeSize uint32

	// Session-node fields.
	LUIDOffset     uint32
	UserNameOffset uint32 // UNICODE_STRING (16 bytes)
	DomainOffset   uint32 // UNICODE_STRING
	PasswordOffset uint32 // UNICODE_STRING (encrypted)

	// LUIDFallbackOffsets tries each in order if the primary LUID
	// reads as 0 (Microsoft has shifted the LUID's position in the
	// node across LCUs). Optional — leave nil to skip the fallback
	// scan.
	LUIDFallbackOffsets []uint32

	// TicketListOffsets is the slice of pointer-to-LIST_ENTRY values
	// inside the session node. Each pointer is the head of a
	// doubly-linked list of KIWI_KERBEROS_INTERNAL_TICKET nodes.
	// Typical Win 7+ session has 3 caches at offsets 280, 304, 328.
	TicketListOffsets []uint32

	// Per-ticket field offsets inside KIWI_KERBEROS_INTERNAL_TICKET.
	TicketServiceNameOffset uint32 // KIWI_KERBEROS_EXTERNAL_NAME*
	TicketTargetNameOffset  uint32 // KIWI_KERBEROS_EXTERNAL_NAME*
	TicketClientNameOffset  uint32 // KIWI_KERBEROS_EXTERNAL_NAME*
	TicketFlagsOffset       uint32 // u32
	TicketKeyTypeOffset     uint32 // u32 — etype: 17=AES128, 18=AES256, 23=RC4-HMAC, 1/3=DES
	TicketEncTypeOffset     uint32 // u32 — kerb-encType
	TicketKvnoOffset        uint32 // u32
	TicketBufferLenOffset   uint32 // u32 (the ticket buffer's length)
	TicketBufferPtrOffset   uint32 // u64 (pointer to the ASN.1 ticket bytes)

	// TicketNodeSize is the smallest ticket size that covers every
	// offset above. Set to ≥ TicketBufferPtrOffset+8 — defaults to
	// 0x180 if zero.
	TicketNodeSize uint32
}

// KerberosTicket is one entry from a session's ticket cache. Buffer
// is the ASN.1-encoded ticket bytes — feed them to a downstream
// Kerberos parser (e.g., impacket / Rubeus / pypykatz's `kerberos
// ccache`) for protocol-level inspection.
type KerberosTicket struct {
	ServiceName string // e.g., "krbtgt"
	TargetName  string // e.g., "DOMAIN.LOCAL"
	ClientName  string // e.g., "alice@CORP.LOCAL"
	Flags       uint32
	KeyType     uint32 // 17=AES128, 18=AES256, 23=RC4-HMAC
	EncType     uint32
	KVNO        uint32
	Buffer      []byte
}

// KerberosCredential is the credential payload extracted from a
// single Kerberos logon session. Password is the plaintext after
// LSA decrypt (rarely populated outside fresh-logon sessions).
// Tickets is the union of every cache (TGT + TGS + …) we walked.
type KerberosCredential struct {
	UserName    string
	LogonDomain string
	Password    string
	Tickets     []KerberosTicket
	Found       bool
}

// AuthPackage satisfies the Credential interface.
func (KerberosCredential) AuthPackage() string { return "Kerberos" }

// String renders Domain\User:Password with a ticket-count summary —
// log-friendly without dumping the full ticket buffers.
func (c KerberosCredential) String() string {
	user := c.UserName
	if c.LogonDomain != "" {
		user = c.LogonDomain + `\` + user
	}
	return fmt.Sprintf("%s:%s [%d ticket(s)]", user, c.Password, len(c.Tickets))
}

// wipe satisfies the optional wipe interface that Result.Wipe calls.
// Plaintext password + every ticket buffer are sensitive — zeroize
// before discarding.
func (c *KerberosCredential) wipe() {
	c.Password = ""
	for i := range c.Tickets {
		for j := range c.Tickets[i].Buffer {
			c.Tickets[i].Buffer[j] = 0
		}
		c.Tickets[i].Buffer = nil
	}
	c.Tickets = nil
	c.Found = false
}

// extractKerberos walks kerberos.dll's KIWI_KERBEROS_LOGON_SESSION
// AVL tree and returns one KerberosCredential per LUID. Each
// credential carries the decrypted password (when present) plus
// every ticket from the session's caches.
//
// Returns (nil, nil) without warning when the template lacks
// Kerberos support (KerberosLayout.NodeSize == 0).
//
// Vista+ Kerberos uses an RTL_AVL_TABLE for session enumeration —
// the rel32 lands on the table's BalancedRoot (sentinel), and the
// actual tree root is `BalancedRoot.RightChild` (table+0x10). We
// recursively in-order walk every node and project each through
// the layout.
func extractKerberos(r *reader, kerbModule Module, t *Template, lsaKey *lsaKey) (map[uint64]KerberosCredential, []string) {
	if t.KerberosLayout.NodeSize == 0 || len(t.KerberosListPattern) == 0 {
		return nil, nil
	}

	body, err := r.ReadVA(kerbModule.BaseOfImage, int(kerbModule.SizeOfImage))
	if err != nil {
		return nil, []string{fmt.Sprintf("Kerberos: read kerberos.dll body: %v", err)}
	}

	tableVA, err := derefRel32(
		body,
		kerbModule.BaseOfImage,
		t.KerberosListPattern,
		t.KerberosListWildcards,
		t.KerberosListOffset,
		r,
	)
	if err != nil {
		return nil, []string{fmt.Sprintf("Kerberos list head: %v", err)}
	}

	// The rel32 lands on the RTL_AVL_TABLE's BalancedRoot sentinel.
	// The actual tree root is BalancedRoot.RightChild (offset +0x10).
	treeRoot := readAVLTreeRoot(r, tableVA)
	if treeRoot == 0 {
		return nil, nil
	}

	creds := make(map[uint64]KerberosCredential)
	var warnings []string

	const maxNodes = 1024
	walkAVL(r, treeRoot, maxNodes, func(addr uint64) {
		node, err := r.ReadVA(addr, int(t.KerberosLayout.NodeSize))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Kerberos node @0x%X: %v", addr, err))
			return
		}
		cred, luid, warn := decodeKerberosSession(r, node, t, lsaKey)
		if warn != "" {
			warnings = append(warnings, warn)
		}
		if cred.Found && luid != 0 {
			// Coalesce duplicate LUIDs (the same logon session can
			// appear in multiple cache trees with different ticket
			// counts). Keep the entry with the longest ticket cache.
			if existing, ok := creds[luid]; !ok || len(cred.Tickets) > len(existing.Tickets) {
				creds[luid] = cred
			}
		}
	})

	return creds, warnings
}

// decodeKerberosSession projects a node-bytes blob through the
// layout to a (KerberosCredential, LUID). On read errors the
// session is skipped with a non-fatal warning.
func decodeKerberosSession(r *reader, node []byte, t *Template, lsaKey *lsaKey) (KerberosCredential, uint64, string) {
	l := t.KerberosLayout
	if uint32(len(node)) < l.NodeSize {
		return KerberosCredential{}, 0, fmt.Sprintf("Kerberos node too small: %d < %d", len(node), l.NodeSize)
	}

	luid := binary.LittleEndian.Uint64(node[l.LUIDOffset : l.LUIDOffset+8])
	// LUID fallback scan: trigger when the primary read is zero OR
	// when the read has its upper 32 bits set (real LUIDs allocated
	// by NT are sequential from 1 and stay well under 2^32 in
	// practice — an upper-32 bit non-zero value is almost always
	// a stray pointer or unrelated field misread). Try each
	// alternate offset until a plausible LUID surfaces.
	if luid == 0 || luid>>32 != 0 {
		for _, off := range l.LUIDFallbackOffsets {
			if off+8 > l.NodeSize {
				continue
			}
			v := binary.LittleEndian.Uint64(node[off : off+8])
			if v != 0 && v>>32 == 0 {
				luid = v
				break
			}
		}
	}

	username := readUnicodeString(r, node[l.UserNameOffset:l.UserNameOffset+16])
	domain := readUnicodeString(r, node[l.DomainOffset:l.DomainOffset+16])

	// Password (UNICODE_STRING with encrypted Buffer). Decryption
	// failure is non-fatal — we still return tickets if present.
	var password string
	pwdField := node[l.PasswordOffset : l.PasswordOffset+16]
	pwdLen := binary.LittleEndian.Uint16(pwdField[0:2])
	pwdBufPtr := binary.LittleEndian.Uint64(pwdField[8:16])
	if pwdLen > 0 && pwdBufPtr != 0 {
		if ct, err := r.ReadVA(pwdBufPtr, int(pwdLen)); err == nil {
			if pt, err := decryptLSA(ct, lsaKey); err == nil {
				password = decodeUTF16LEBytes(pt)
			}
		}
	}

	// Walk every ticket cache pointed to by the session node. Each
	// "ticket list" is an embedded LIST_ENTRY whose Flink heads the
	// chain of KIWI_KERBEROS_INTERNAL_TICKET nodes.
	var tickets []KerberosTicket
	for _, listOff := range l.TicketListOffsets {
		if listOff+16 > l.NodeSize {
			continue
		}
		flink := binary.LittleEndian.Uint64(node[listOff : listOff+8])
		if flink == 0 {
			continue
		}
		tickets = append(tickets, walkKerberosTickets(r, flink, l)...)
	}

	cred := KerberosCredential{
		UserName:    username,
		LogonDomain: domain,
		Password:    password,
		Tickets:     tickets,
		Found:       username != "" || password != "" || len(tickets) > 0,
	}
	return cred, luid, ""
}

// walkKerberosTickets follows a ticket cache's Flink chain and reads
// every ticket found, capped at 256 to defeat malformed dumps.
//
// The ticket-list head lives INSIDE the session node (an embedded
// LIST_ENTRY), so we don't have a separate "list head VA" to compare
// against for loop termination. The walk terminates on:
//   - the 256-ticket cap, or
//   - a self-pointer (Flink == cur), or
//   - any ReadVA failure on the next node.
// In practice every Kerberos cache wraps within ~16 tickets so the
// cap never trips on a healthy dump.
func walkKerberosTickets(r *reader, head uint64, l KerberosLayout) []KerberosTicket {
	var out []KerberosTicket
	// Real Kerberos cache wraps within ~5-20 tickets per session;
	// 32 is a generous cap that limits junk-ticket runaway when our
	// per-build offsets are misaligned and we end up walking arbitrary
	// memory. Per-build field-offset refinement is queued for v0.30.x.
	const maxTickets = 32
	tnSize := l.TicketNodeSize
	if tnSize == 0 {
		tnSize = 0x180
	}

	walked := 0
	cur := head
	for cur != 0 && walked < maxTickets {
		ticket, err := readKerberosTicket(r, cur, l, tnSize)
		if err != nil {
			break
		}
		out = append(out, ticket)
		next, err := readPointer(r, cur)
		if err != nil || next == 0 || next == cur {
			break
		}
		cur = next
		walked++
	}
	return out
}

// readKerberosTicket reads one KIWI_KERBEROS_INTERNAL_TICKET at the
// given VA and projects it through the layout's per-ticket offsets.
func readKerberosTicket(r *reader, va uint64, l KerberosLayout, tnSize uint32) (KerberosTicket, error) {
	node, err := r.ReadVA(va, int(tnSize))
	if err != nil {
		return KerberosTicket{}, err
	}

	t := KerberosTicket{}

	// Names — each is a pointer to a KIWI_KERBEROS_EXTERNAL_NAME
	// struct whose first UNICODE_STRING sits at +8. readExternalName
	// returns "" on any read failure.
	if l.TicketServiceNameOffset+8 <= tnSize {
		t.ServiceName = readExternalName(r, binary.LittleEndian.Uint64(
			node[l.TicketServiceNameOffset:l.TicketServiceNameOffset+8]))
	}
	if l.TicketTargetNameOffset+8 <= tnSize {
		t.TargetName = readExternalName(r, binary.LittleEndian.Uint64(
			node[l.TicketTargetNameOffset:l.TicketTargetNameOffset+8]))
	}
	if l.TicketClientNameOffset+8 <= tnSize {
		t.ClientName = readExternalName(r, binary.LittleEndian.Uint64(
			node[l.TicketClientNameOffset:l.TicketClientNameOffset+8]))
	}

	if l.TicketFlagsOffset+4 <= tnSize {
		t.Flags = binary.LittleEndian.Uint32(node[l.TicketFlagsOffset : l.TicketFlagsOffset+4])
	}
	if l.TicketKeyTypeOffset+4 <= tnSize {
		t.KeyType = binary.LittleEndian.Uint32(node[l.TicketKeyTypeOffset : l.TicketKeyTypeOffset+4])
	}
	if l.TicketEncTypeOffset+4 <= tnSize {
		t.EncType = binary.LittleEndian.Uint32(node[l.TicketEncTypeOffset : l.TicketEncTypeOffset+4])
	}
	if l.TicketKvnoOffset+4 <= tnSize {
		t.KVNO = binary.LittleEndian.Uint32(node[l.TicketKvnoOffset : l.TicketKvnoOffset+4])
	}

	if l.TicketBufferLenOffset+4 <= tnSize && l.TicketBufferPtrOffset+8 <= tnSize {
		bufLen := binary.LittleEndian.Uint32(node[l.TicketBufferLenOffset : l.TicketBufferLenOffset+4])
		bufPtr := binary.LittleEndian.Uint64(node[l.TicketBufferPtrOffset : l.TicketBufferPtrOffset+8])
		// Cap at 64KB — real Kerberos tickets are well under 16KB,
		// anything larger signals a corrupted dump or wrong layout.
		if bufLen > 0 && bufLen < 65536 && bufPtr != 0 {
			if buf, err := r.ReadVA(bufPtr, int(bufLen)); err == nil {
				out := make([]byte, len(buf))
				copy(out, buf)
				t.Buffer = out
			}
		}
	}

	return t, nil
}

// readExternalName dereferences a KIWI_KERBEROS_EXTERNAL_NAME
// pointer and returns its first UNICODE_STRING component as a Go
// string. Multi-component names join with "/".
//
// Layout (stable across builds):
//
//	+0x00  NameType  uint16
//	+0x02  pad
//	+0x04  NameCount uint16
//	+0x08  first UNICODE_STRING (16 bytes; KvcForensic
//	       external_name_first_string_offset = 8)
//	+0x18  second UNICODE_STRING …
func readExternalName(r *reader, ptr uint64) string {
	if ptr == 0 {
		return ""
	}
	const headerSize = 8
	header, err := r.ReadVA(ptr, headerSize)
	if err != nil {
		return ""
	}
	count := binary.LittleEndian.Uint16(header[4:6])
	if count == 0 || count > 16 {
		return ""
	}

	parts := make([]string, 0, count)
	for i := uint16(0); i < count; i++ {
		field, err := r.ReadVA(ptr+8+uint64(i)*16, 16)
		if err != nil {
			break
		}
		parts = append(parts, readUnicodeString(r, field))
	}
	return joinNonEmpty(parts, "/")
}

// joinNonEmpty joins non-empty strings with sep — stdlib strings.Join
// would emit "alice//corp" if any component is empty, which we don't
// want for partial reads.
func joinNonEmpty(parts []string, sep string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += sep
		}
		out += p
	}
	return out
}

// mergeKerberos grafts Kerberos credentials onto matching
// LogonSessions by LUID, mirroring mergeWdigest / mergeDPAPI /
// mergeTSPkg semantics. Orphan Kerberos LUIDs surface as new
// sessions.
func mergeKerberos(sessions []LogonSession, kerb map[uint64]KerberosCredential) []LogonSession {
	if len(kerb) == 0 {
		return sessions
	}
	seen := make(map[uint64]bool, len(sessions))
	for i := range sessions {
		if c, ok := kerb[sessions[i].LUID]; ok {
			sessions[i].Credentials = append(sessions[i].Credentials, c)
			seen[sessions[i].LUID] = true
		}
	}
	for luid, c := range kerb {
		if seen[luid] {
			continue
		}
		sessions = append(sessions, LogonSession{
			LUID:        luid,
			UserName:    c.UserName,
			LogonDomain: c.LogonDomain,
			Credentials: []Credential{c},
		})
	}
	return sessions
}
