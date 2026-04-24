package lsassdump

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// sampleConfig returns a Config with two memory regions, one module,
// one thread, and a Win10 22H2 amd64 SystemInfo.
func sampleConfig() Config {
	return Config{
		TimeDateStamp: 0xDEADBEEF,
		SystemInfo: SystemInfo{
			ProcessorArchitecture: 9, // AMD64
			NumberOfProcessors:    4,
			ProductType:           1, // workstation
			MajorVersion:          10,
			BuildNumber:           19045,
			PlatformID:            2, // NT
			CSDVersion:            "Service Pack Test",
		},
		Modules: []Module{
			{
				BaseOfImage:   0x7FFE00000000,
				SizeOfImage:   0x100000,
				TimeDateStamp: 0x60000000,
				Name:          "lsasrv.dll",
			},
		},
		Threads: []Thread{
			{
				ThreadID:     42,
				SuspendCount: 0,
				Teb:          0x7FF800000000,
				StackStart:   0x7FF100000000,
				StackData:    bytes.Repeat([]byte{0xAA}, 256),
				ContextBytes: bytes.Repeat([]byte{0xCC}, 1232), // amd64 CONTEXT size
			},
		},
		Regions: []MemoryRegion{
			{BaseAddress: 0x10000, Data: bytes.Repeat([]byte{0x11}, 4096)},
			{BaseAddress: 0x20000, Data: bytes.Repeat([]byte{0x22}, 8192)},
		},
	}
}

func TestBuild_Header(t *testing.T) {
	var buf bytes.Buffer
	stats, err := Build(&buf, sampleConfig())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw := buf.Bytes()
	if len(raw) < 32 {
		t.Fatalf("dump too small: %d", len(raw))
	}

	sig := binary.LittleEndian.Uint32(raw[0:4])
	if sig != miniDumpSignature {
		t.Fatalf("bad signature: got 0x%X, want 0x504D444D", sig)
	}
	ver := binary.LittleEndian.Uint32(raw[4:8])
	if ver != miniDumpVersion {
		t.Fatalf("bad version: got %d, want %d", ver, miniDumpVersion)
	}
	numStreams := binary.LittleEndian.Uint32(raw[8:12])
	if numStreams != 4 {
		t.Fatalf("bad stream count: got %d, want 4", numStreams)
	}
	dirRva := binary.LittleEndian.Uint32(raw[12:16])
	if dirRva != 32 {
		t.Fatalf("directory RVA should be 32 (right after header), got %d", dirRva)
	}
	tds := binary.LittleEndian.Uint32(raw[20:24])
	if tds != 0xDEADBEEF {
		t.Fatalf("bad TimeDateStamp: got 0x%X", tds)
	}

	if stats.Regions != 2 || stats.ModuleCount != 1 || stats.ThreadCount != 1 {
		t.Fatalf("bad stats: %+v", stats)
	}
	if stats.Bytes != 4096+8192 {
		t.Fatalf("stats.Bytes wrong: got %d, want %d", stats.Bytes, 4096+8192)
	}
}

func TestBuild_DirectoryContainsAllStreams(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Build(&buf, sampleConfig()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw := buf.Bytes()

	want := map[uint32]bool{
		streamSystemInfo:   false,
		streamThreadList:   false,
		streamModuleList:   false,
		streamMemory64List: false,
	}

	for i := 0; i < 4; i++ {
		off := 32 + i*12
		streamType := binary.LittleEndian.Uint32(raw[off : off+4])
		streamSize := binary.LittleEndian.Uint32(raw[off+4 : off+8])
		streamRva := binary.LittleEndian.Uint32(raw[off+8 : off+12])
		if _, ok := want[streamType]; !ok {
			t.Errorf("unexpected stream type 0x%X in directory slot %d", streamType, i)
			continue
		}
		want[streamType] = true
		if streamSize == 0 {
			t.Errorf("stream type 0x%X has zero size", streamType)
		}
		if int(streamRva)+int(streamSize) > len(raw) {
			t.Errorf("stream type 0x%X extends past EOF: rva=%d size=%d filelen=%d",
				streamType, streamRva, streamSize, len(raw))
		}
	}

	for t32, saw := range want {
		if !saw {
			t.Errorf("directory missing stream type 0x%X", t32)
		}
	}
}

func TestBuild_Memory64PayloadsRoundtrip(t *testing.T) {
	cfg := sampleConfig()
	var buf bytes.Buffer
	if _, err := Build(&buf, cfg); err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw := buf.Bytes()

	// Find the Memory64List directory entry.
	var memRva, memSize uint32
	for i := 0; i < 4; i++ {
		off := 32 + i*12
		if binary.LittleEndian.Uint32(raw[off:off+4]) == streamMemory64List {
			memSize = binary.LittleEndian.Uint32(raw[off+4 : off+8])
			memRva = binary.LittleEndian.Uint32(raw[off+8 : off+12])
			break
		}
	}
	if memRva == 0 {
		t.Fatal("Memory64ListStream not in directory")
	}

	nRanges := binary.LittleEndian.Uint64(raw[memRva : memRva+8])
	baseRva := binary.LittleEndian.Uint64(raw[memRva+8 : memRva+16])
	if nRanges != uint64(len(cfg.Regions)) {
		t.Fatalf("range count mismatch: got %d, want %d", nRanges, len(cfg.Regions))
	}
	if int(memRva)+int(memSize) > len(raw) || baseRva >= uint64(len(raw)) {
		t.Fatalf("bad RVAs: memRva=%d memSize=%d baseRva=%d filelen=%d",
			memRva, memSize, baseRva, len(raw))
	}

	// Walk descriptors, verify payloads match.
	cursor := baseRva
	for i, r := range cfg.Regions {
		descOff := int(memRva) + 16 + i*16
		start := binary.LittleEndian.Uint64(raw[descOff : descOff+8])
		size := binary.LittleEndian.Uint64(raw[descOff+8 : descOff+16])
		if start != r.BaseAddress {
			t.Errorf("region %d: start mismatch got 0x%X want 0x%X", i, start, r.BaseAddress)
		}
		if size != uint64(len(r.Data)) {
			t.Errorf("region %d: size mismatch got %d want %d", i, size, len(r.Data))
		}
		got := raw[cursor : cursor+size]
		if !bytes.Equal(got, r.Data) {
			t.Errorf("region %d: payload mismatch (first bytes got=%x want=%x)",
				i, got[:4], r.Data[:4])
		}
		cursor += size
	}
}

func TestBuild_EmptyRegions(t *testing.T) {
	// A dump with zero memory regions, zero modules, zero threads is
	// still well-formed — the Memory64List header ends with 0 ranges.
	var buf bytes.Buffer
	stats, err := Build(&buf, Config{SystemInfo: SystemInfo{ProcessorArchitecture: 9}})
	if err != nil {
		t.Fatalf("Build empty: %v", err)
	}
	if stats.Regions != 0 || stats.Bytes != 0 {
		t.Fatalf("empty stats wrong: %+v", stats)
	}
	raw := buf.Bytes()
	if binary.LittleEndian.Uint32(raw[0:4]) != miniDumpSignature {
		t.Fatal("empty dump lacks MDMP signature")
	}
}

func TestStringSize(t *testing.T) {
	// MINIDUMP_STRING = 4 (length) + 2·chars + 2 (NUL)
	cases := map[string]uint32{
		"":       4 + 0 + 2,
		"abc":    4 + 6 + 2,
		"lsasrv": 4 + 12 + 2,
	}
	for s, want := range cases {
		if got := stringSize(s); got != want {
			t.Errorf("stringSize(%q) = %d, want %d", s, got, want)
		}
	}
}
