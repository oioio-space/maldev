package sekurlsa

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/oioio-space/maldev/credentials/lsassdump"
)

// avlSyntheticTree builds a synthetic minidump fixture with three
// AVL nodes laid out as a balanced 3-node tree:
//
//	    NODE_B
//	   /      \
//	NODE_A   NODE_C
//
// Each node has 24 bytes of RTL_BALANCED_LINKS at offset 0
// (Parent + LeftChild + RightChild). Returns the dump blob, the
// root node VA, and the per-node VAs for assertions.
func avlSyntheticTree(t *testing.T) (blob []byte, root, nodeA, nodeB, nodeC uint64) {
	t.Helper()

	const (
		modBase uint64 = 0x7FF800000000
		modSize        = uint32(0x1000)

		// Each node sits at its own page-aligned VA past the module image.
		vNodeA uint64 = modBase + uint64(modSize) + 0x100
		vNodeB uint64 = modBase + uint64(modSize) + 0x200
		vNodeC uint64 = modBase + uint64(modSize) + 0x300
	)

	mkNode := func(parent, left, right uint64) []byte {
		buf := make([]byte, 0x20)
		binary.LittleEndian.PutUint64(buf[0x00:0x08], parent)
		binary.LittleEndian.PutUint64(buf[0x08:0x10], left)
		binary.LittleEndian.PutUint64(buf[0x10:0x18], right)
		return buf
	}

	// B is the root (its parent is the sentinel, which we just leave 0).
	bytesA := mkNode(vNodeB, 0, 0)
	bytesB := mkNode(0, vNodeA, vNodeC)
	bytesC := mkNode(vNodeB, 0, 0)

	regions := []lsassdump.MemoryRegion{
		{BaseAddress: modBase, Data: make([]byte, modSize)},
		{BaseAddress: vNodeA, Data: bytesA},
		{BaseAddress: vNodeB, Data: bytesB},
		{BaseAddress: vNodeC, Data: bytesC},
	}
	mods := []lsassdump.Module{
		{BaseOfImage: modBase, SizeOfImage: modSize, Name: "kerberos.dll"},
	}
	blob = buildFixture(t, mods, regions)
	return blob, vNodeB, vNodeA, vNodeB, vNodeC
}

// TestWalkAVL_InOrder verifies the helper visits all 3 nodes of a
// balanced synthetic tree in left/self/right order.
func TestWalkAVL_InOrder(t *testing.T) {
	blob, root, nA, nB, nC := avlSyntheticTree(t)
	r, err := openReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("openReader: %v", err)
	}

	var visited []uint64
	walkAVL(r, root, 100, func(addr uint64) {
		visited = append(visited, addr)
	})

	want := []uint64{nA, nB, nC} // in-order
	if len(visited) != len(want) {
		t.Fatalf("visited %d nodes, want %d (got %v)", len(visited), len(want), visited)
	}
	for i, w := range want {
		if visited[i] != w {
			t.Errorf("visited[%d] = 0x%X, want 0x%X", i, visited[i], w)
		}
	}
}

// TestWalkAVL_NilRoot — empty tree → no visit.
func TestWalkAVL_NilRoot(t *testing.T) {
	called := 0
	walkAVL(nil, 0, 100, func(uint64) { called++ })
	if called != 0 {
		t.Errorf("visit called %d times on nil root, want 0", called)
	}
}

// TestWalkAVL_MaxNodes bounds the traversal — feed a tree with 3
// nodes but cap at 1, expect 1 visit.
func TestWalkAVL_MaxNodes(t *testing.T) {
	blob, root, _, _, _ := avlSyntheticTree(t)
	r, err := openReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("openReader: %v", err)
	}
	count := 0
	walkAVL(r, root, 1, func(uint64) { count++ })
	if count != 1 {
		t.Errorf("visited %d, want 1 (maxNodes cap)", count)
	}
}

// TestWalkAVL_DefeatsCycle — a corrupted tree where node A's left
// child is itself must terminate via the visited-set guard rather
// than spinning.
func TestWalkAVL_DefeatsCycle(t *testing.T) {
	const (
		modBase uint64 = 0x7FF800000000
		modSize        = uint32(0x1000)
		vNode   uint64 = modBase + uint64(modSize) + 0x100
	)

	// Self-referencing node: LeftChild points back at itself.
	cyclic := make([]byte, 0x20)
	binary.LittleEndian.PutUint64(cyclic[0x08:0x10], vNode) // LeftChild = self

	regions := []lsassdump.MemoryRegion{
		{BaseAddress: modBase, Data: make([]byte, modSize)},
		{BaseAddress: vNode, Data: cyclic},
	}
	mods := []lsassdump.Module{
		{BaseOfImage: modBase, SizeOfImage: modSize, Name: "x.dll"},
	}
	blob := buildFixture(t, mods, regions)
	r, err := openReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("openReader: %v", err)
	}

	count := 0
	walkAVL(r, vNode, 100, func(uint64) { count++ })
	if count != 1 {
		t.Errorf("visited %d, want 1 (cycle detection)", count)
	}
}

// TestReadAVLTreeRoot — the helper dereferences `tableVA + 0x10`
// (BalancedRoot.RightChild) to get the actual tree root.
func TestReadAVLTreeRoot(t *testing.T) {
	const (
		modBase  uint64 = 0x7FF800000000
		modSize         = uint32(0x1000)
		vTable   uint64 = modBase + uint64(modSize) + 0x100
		wantRoot uint64 = 0xCAFEBABE12345678
	)

	// RTL_AVL_TABLE: 32 bytes BalancedRoot followed by other fields.
	// We only need bytes 0x10..0x18 (RightChild).
	tab := make([]byte, 0x40)
	binary.LittleEndian.PutUint64(tab[0x10:0x18], wantRoot)

	regions := []lsassdump.MemoryRegion{
		{BaseAddress: modBase, Data: make([]byte, modSize)},
		{BaseAddress: vTable, Data: tab},
	}
	mods := []lsassdump.Module{
		{BaseOfImage: modBase, SizeOfImage: modSize, Name: "x.dll"},
	}
	blob := buildFixture(t, mods, regions)
	r, err := openReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("openReader: %v", err)
	}

	got := readAVLTreeRoot(r, vTable)
	if got != wantRoot {
		t.Errorf("readAVLTreeRoot = 0x%X, want 0x%X", got, wantRoot)
	}
}
