package sekurlsa

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"
)

// TestKerbProbe — env-gated dump introspection. For each candidate
// in {globalVA, *globalVA}, dump 64 bytes and compute heuristics
// (looks-like-AVL? has-Win10-VA-prefix?) to decide which is the
// real RTL_AVL_TABLE. Helps verify whether v0.30.2's extra
// pointer dereference is the right call on a specific build.
//
// Run: MALDEV_REALDUMP=ignore/lsass-dumps/win10-22h2-19045.dmp \
//      go test ./credentials/sekurlsa/... -run TestKerbProbe -v
func TestKerbProbe(t *testing.T) {
	dumpPath := os.Getenv("MALDEV_REALDUMP")
	if dumpPath == "" {
		t.Skip("set MALDEV_REALDUMP=<path> to run")
	}
	f, err := os.Open(dumpPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	st, _ := f.Stat()
	r, err := openReader(f, st.Size())
	if err != nil {
		t.Fatalf("openReader: %v", err)
	}

	res := &Result{
		Modules: modulesFromReader(r),
	}
	mod, ok := res.ModuleByName("kerberos.dll")
	if !ok {
		t.Fatal("kerberos.dll missing")
	}

	body, err := r.ReadVA(mod.BaseOfImage, int(mod.SizeOfImage))
	if err != nil {
		t.Fatalf("read kerberos body: %v", err)
	}

	sig := []byte{0x48, 0x8B, 0x18, 0x48, 0x8D, 0x0D}
	matchAt := findPattern(body, sig, nil)
	if matchAt < 0 {
		t.Fatal("Kerberos signature not found")
	}
	t.Logf("signature @ module-RVA 0x%X (VA 0x%X)", matchAt, mod.BaseOfImage+uint64(matchAt))

	// derefRel32 with our default offset 6.
	relAt := matchAt + 6
	if relAt+4 > len(body) {
		t.Fatalf("rel32 OOB")
	}
	rel32 := int32(binary.LittleEndian.Uint32(body[relAt : relAt+4]))
	globalVA := uint64(int64(mod.BaseOfImage) + int64(relAt) + 4 + int64(rel32))
	t.Logf("rel32 = 0x%X → globalVA = 0x%X", rel32, globalVA)

	dump := func(label string, va uint64) {
		buf, err := r.ReadVA(va, 64)
		if err != nil {
			t.Logf("%-10s @0x%X: read error: %v", label, va, err)
			return
		}
		// Pretty hex with 8-byte u64 reads.
		t.Logf("=== %s @0x%X ===", label, va)
		for i := 0; i+8 <= len(buf); i += 8 {
			ptr := binary.LittleEndian.Uint64(buf[i : i+8])
			marker := ""
			// Win 10 user-space VAs are typically 0x7FF8xxxxxxxx or 0x7FFFxxxxxxxx;
			// kernel-space starts at 0xFFFF800000000000+. Mark plausible userland pointers.
			if ptr >= 0x7FF000000000 && ptr < 0x80000000000 {
				marker = " <-- userland pointer"
			}
			t.Logf("  +0x%02X: 0x%016X%s", i, ptr, marker)
		}
	}

	dump("globalVA", globalVA)
	derefVA, err := readPointer(r, globalVA)
	if err == nil {
		dump("*globalVA (pypykatz table_ptr)", derefVA)
	} else {
		t.Logf("readPointer(globalVA): %v", err)
	}

	// AVL-table sniffer: an RTL_AVL_TABLE has BalancedRoot.Parent=0
	// (sentinel), LeftChild=0 (sentinel), RightChild=<userland VA>.
	// So if dump shows +0x00=0 +0x08=0 +0x10=<userland>, it IS the table.
	check := func(label string, va uint64) {
		buf, err := r.ReadVA(va, 24)
		if err != nil {
			return
		}
		parent := binary.LittleEndian.Uint64(buf[0:8])
		left := binary.LittleEndian.Uint64(buf[8:16])
		right := binary.LittleEndian.Uint64(buf[16:24])
		looksLikeTable := parent == 0 && left == 0 &&
			right >= 0x7FF000000000 && right < 0x80000000000
		t.Logf("%-30s: Parent=0x%X Left=0x%X Right=0x%X looksLikeAVL=%v",
			label, parent, left, right, looksLikeTable)
	}
	check("globalVA itself", globalVA)
	if err == nil {
		check("*globalVA", derefVA)
	}

	// Print readable msg for which is correct.
	fmt.Println("---")
}
