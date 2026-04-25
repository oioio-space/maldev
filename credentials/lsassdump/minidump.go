package lsassdump

import (
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

// MINIDUMP format reference: MSDN "MINIDUMP_HEADER" and friends,
// winnt.h / minidumpapiset.h. All fields are little-endian.
//
// Layout written by Build:
//
//   [MINIDUMP_HEADER]                            32 B
//   [MINIDUMP_DIRECTORY × NumStreams]            12 B each
//   [SystemInfo stream]                          56 B
//   [ThreadList stream]                          4 + 48·N
//   [ModuleList stream]                          4 + 108·M
//   [module name MINIDUMP_STRINGs]               (4 + 2·len) each
//   [Memory64List stream header + descriptors]   16 + 16·R
//   [raw memory regions]                         sum(Data)
//
// Only streams required by mimikatz/pypykatz are emitted. Everything
// else (HandleData, MemoryInfoList, ThreadInfoList, …) is optional
// for credential parsers and is skipped to keep the writer lean.

// Stream types we emit. See MINIDUMP_STREAM_TYPE enum.
const (
	streamThreadList   uint32 = 3
	streamModuleList   uint32 = 4
	streamSystemInfo   uint32 = 7
	streamMemory64List uint32 = 9
)

const (
	miniDumpSignature = 0x504D444D // "MDMP"
	miniDumpVersion   = 42899      // 0xA793
)

// MemoryRegion is one contiguous chunk of memory captured from the
// target process.
type MemoryRegion struct {
	BaseAddress uint64
	Data        []byte
}

// Module is a loaded module in the target process. The subset here is
// the MINIDUMP_MODULE fields credential parsers actually read.
type Module struct {
	BaseOfImage   uint64
	SizeOfImage   uint32
	TimeDateStamp uint32
	CheckSum      uint32
	Name          string
}

// Thread describes a thread captured from the target. ContextBytes is
// the raw CONTEXT structure (amd64 CONTEXT is 1232 bytes); callers that
// don't have a context may pass nil — StackStart/StackData populate the
// Stack descriptor which is what most parsers care about.
type Thread struct {
	ThreadID      uint32
	SuspendCount  uint32
	PriorityClass uint32
	Priority      uint32
	Teb           uint64
	StackStart    uint64
	StackData     []byte
	ContextBytes  []byte
}

// SystemInfo is the subset of MINIDUMP_SYSTEM_INFO the dump needs to
// identify the host OS. Credential parsers use it to select per-build
// offset tables. On Windows, Config callers fill it from
// GetVersionEx/GetNativeSystemInfo; for cross-platform tests a literal
// value (e.g. Win10 22H2 amd64) is fine.
type SystemInfo struct {
	ProcessorArchitecture uint16 // 9 = AMD64, 0 = x86
	ProcessorLevel        uint16
	ProcessorRevision     uint16
	NumberOfProcessors    uint8
	ProductType           uint8 // 1 = workstation, 3 = server
	MajorVersion          uint32
	MinorVersion          uint32
	BuildNumber           uint32
	PlatformID            uint32 // 2 = NT
	CSDVersion            string
	SuiteMask             uint16
}

// Config bundles everything Build needs to emit a MINIDUMP.
type Config struct {
	TimeDateStamp uint32
	Flags         uint64
	SystemInfo    SystemInfo
	Modules       []Module
	Threads       []Thread
	Regions       []MemoryRegion
}

// Build writes a MINIDUMP blob describing cfg to w and returns a Stats
// summary. w is written streaming (no in-memory copy of the raw memory
// regions); Build requires two passes over cfg to compute RVAs so w
// MUST be positioned at offset 0 when called.
func Build(w io.Writer, cfg Config) (Stats, error) {
	layout := planLayout(cfg)

	if err := writeHeader(w, layout); err != nil {
		return Stats{}, fmt.Errorf("header: %w", err)
	}
	if err := writeDirectory(w, layout); err != nil {
		return Stats{}, fmt.Errorf("directory: %w", err)
	}
	if err := writeSystemInfo(w, cfg.SystemInfo, layout); err != nil {
		return Stats{}, fmt.Errorf("system info: %w", err)
	}
	if err := writeThreadList(w, cfg.Threads, layout); err != nil {
		return Stats{}, fmt.Errorf("thread list: %w", err)
	}
	if err := writeModuleList(w, cfg.Modules, layout); err != nil {
		return Stats{}, fmt.Errorf("module list: %w", err)
	}
	if err := writeMemory64List(w, cfg.Regions, layout); err != nil {
		return Stats{}, fmt.Errorf("memory64 list: %w", err)
	}

	var totalBytes uint64
	for _, r := range cfg.Regions {
		totalBytes += uint64(len(r.Data))
	}
	return Stats{
		Regions:     len(cfg.Regions),
		Bytes:       totalBytes,
		ModuleCount: len(cfg.Modules),
		ThreadCount: len(cfg.Threads),
	}, nil
}

// layout holds the byte offsets and sizes of every stream so pass 2
// can emit correct RVAs without rewinding the writer.
type layout struct {
	cfg               Config
	numStreams        uint32
	directoryRva      uint32
	systemInfoRva     uint32
	systemInfoSize    uint32
	csdVersionRva     uint32
	csdVersionSize    uint32
	threadListRva     uint32
	threadListSize    uint32
	threadContextsRva uint32
	moduleListRva     uint32
	moduleListSize    uint32
	moduleNamesRva    uint32
	moduleNameRvas    []uint32
	memory64ListRva   uint32
	memory64ListSize  uint32
	memory64BaseRva   uint64
}

func planLayout(cfg Config) *layout {
	L := &layout{cfg: cfg}
	const headerSize = uint32(32)
	const dirEntrySize = uint32(12)

	L.numStreams = 4
	L.directoryRva = headerSize
	off := headerSize + L.numStreams*dirEntrySize

	// SystemInfo stream.
	L.systemInfoRva = off
	L.systemInfoSize = 56
	off += L.systemInfoSize

	// CSDVersion MINIDUMP_STRING immediately after SystemInfo.
	L.csdVersionRva = off
	L.csdVersionSize = stringSize(cfg.SystemInfo.CSDVersion)
	off += L.csdVersionSize

	// ThreadList stream: 4-byte count + 48 bytes per thread.
	L.threadListRva = off
	L.threadListSize = 4 + uint32(len(cfg.Threads))*48
	off += L.threadListSize

	// Raw thread-context buffers packed after the ThreadList.
	L.threadContextsRva = off
	for _, t := range cfg.Threads {
		off += uint32(len(t.ContextBytes))
	}

	// ModuleList stream: 4-byte count + 108 bytes per module.
	L.moduleListRva = off
	L.moduleListSize = 4 + uint32(len(cfg.Modules))*108
	off += L.moduleListSize

	// Module name MINIDUMP_STRINGs packed after the list.
	L.moduleNamesRva = off
	L.moduleNameRvas = make([]uint32, len(cfg.Modules))
	for i, m := range cfg.Modules {
		L.moduleNameRvas[i] = off
		off += stringSize(m.Name)
	}

	// Memory64List stream: 16-byte header + 16 bytes per descriptor.
	L.memory64ListRva = off
	L.memory64ListSize = 16 + uint32(len(cfg.Regions))*16
	off += L.memory64ListSize

	// Raw memory regions start at BaseRva (uint64 in the stream header).
	L.memory64BaseRva = uint64(off)

	return L
}

// stringSize returns the on-disk size of a MINIDUMP_STRING holding s.
// Layout: 4-byte length + UTF-16LE bytes + 2-byte NUL terminator.
func stringSize(s string) uint32 {
	u := utf16.Encode([]rune(s))
	return 4 + uint32(len(u))*2 + 2
}

func writeMinidumpString(w io.Writer, s string) error {
	u := utf16.Encode([]rune(s))
	if err := binary.Write(w, binary.LittleEndian, uint32(len(u)*2)); err != nil {
		return err
	}
	buf := make([]byte, len(u)*2+2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(buf[i*2:], c)
	}
	// trailing NUL already zero.
	_, err := w.Write(buf)
	return err
}

func writeHeader(w io.Writer, L *layout) error {
	return binary.Write(w, binary.LittleEndian, struct {
		Signature     uint32
		Version       uint32
		NumberOfDirs  uint32
		DirectoryRva  uint32
		CheckSum      uint32
		TimeDateStamp uint32
		Flags         uint64
	}{
		Signature:     miniDumpSignature,
		Version:       miniDumpVersion,
		NumberOfDirs:  L.numStreams,
		DirectoryRva:  L.directoryRva,
		CheckSum:      0,
		TimeDateStamp: L.cfg.TimeDateStamp,
		Flags:         L.cfg.Flags,
	})
}

func writeDirectory(w io.Writer, L *layout) error {
	entries := []struct {
		Type uint32
		Size uint32
		Rva  uint32
	}{
		{streamSystemInfo, L.systemInfoSize, L.systemInfoRva},
		{streamThreadList, L.threadListSize, L.threadListRva},
		{streamModuleList, L.moduleListSize, L.moduleListRva},
		{streamMemory64List, L.memory64ListSize, L.memory64ListRva},
	}
	return binary.Write(w, binary.LittleEndian, entries)
}

func writeSystemInfo(w io.Writer, si SystemInfo, L *layout) error {
	// MINIDUMP_SYSTEM_INFO = 56 bytes: 20 bytes of CPU/OS header +
	// 16 bytes CSDVersionRva/SuiteMask/Reserved2 + 24 bytes CPU union.
	// We zero the CPU union — parsers only read it for x86 branches.
	//
	// For layout, see winnt.h / MINIDUMP_SYSTEM_INFO.
	if err := binary.Write(w, binary.LittleEndian, struct {
		ProcessorArchitecture uint16
		ProcessorLevel        uint16
		ProcessorRevision     uint16
		NumberOfProcessors    uint8
		ProductType           uint8
		MajorVersion          uint32
		MinorVersion          uint32
		BuildNumber           uint32
		PlatformID            uint32
		CSDVersionRva         uint32
		SuiteMask             uint16
		Reserved2             uint16
		// CPU union — VendorId[3]×u32 + VersionInformation u32 +
		// FeatureInformation u32 + AMDExtendedCpuFeatures u32 = 24 B.
		CPUVendor0 uint32
		CPUVendor1 uint32
		CPUVendor2 uint32
		CPUVersion uint32
		CPUFeat    uint32
		CPUAMDExt  uint32
	}{
		ProcessorArchitecture: si.ProcessorArchitecture,
		ProcessorLevel:        si.ProcessorLevel,
		ProcessorRevision:     si.ProcessorRevision,
		NumberOfProcessors:    si.NumberOfProcessors,
		ProductType:           si.ProductType,
		MajorVersion:          si.MajorVersion,
		MinorVersion:          si.MinorVersion,
		BuildNumber:           si.BuildNumber,
		PlatformID:            si.PlatformID,
		CSDVersionRva:         L.csdVersionRva,
		SuiteMask:             si.SuiteMask,
	}); err != nil {
		return err
	}
	return writeMinidumpString(w, si.CSDVersion)
}

func writeThreadList(w io.Writer, ts []Thread, L *layout) error {
	if err := binary.Write(w, binary.LittleEndian, uint32(len(ts))); err != nil {
		return err
	}
	ctxOff := L.threadContextsRva
	for _, t := range ts {
		stackRva := uint32(0)
		stackSize := uint32(0)
		// Stack data is emitted inline with the memory regions; for the
		// MVP we point the Stack descriptor at the first Region whose
		// range covers StackStart, or zero if none.
		if len(t.StackData) > 0 {
			// Place the stack bytes inside the Memory64 blob: callers
			// that want the stack searchable via MiniDumpReadDump must
			// also include the stack range in cfg.Regions. The
			// MINIDUMP_MEMORY_DESCRIPTOR here carries the size but
			// points Rva=0 to signal "find it in Memory64List".
			stackSize = uint32(len(t.StackData))
		}
		if err := binary.Write(w, binary.LittleEndian, struct {
			ThreadID      uint32
			SuspendCount  uint32
			PriorityClass uint32
			Priority      uint32
			Teb           uint64
			StackStart    uint64
			StackSize     uint32
			StackRva      uint32
			ContextSize   uint32
			ContextRva    uint32
		}{
			ThreadID:      t.ThreadID,
			SuspendCount:  t.SuspendCount,
			PriorityClass: t.PriorityClass,
			Priority:      t.Priority,
			Teb:           t.Teb,
			StackStart:    t.StackStart,
			StackSize:     stackSize,
			StackRva:      stackRva,
			ContextSize:   uint32(len(t.ContextBytes)),
			ContextRva:    ctxOff,
		}); err != nil {
			return err
		}
		ctxOff += uint32(len(t.ContextBytes))
	}
	// Emit the raw context bytes immediately after the list.
	for _, t := range ts {
		if len(t.ContextBytes) == 0 {
			continue
		}
		if _, err := w.Write(t.ContextBytes); err != nil {
			return err
		}
	}
	return nil
}

func writeModuleList(w io.Writer, ms []Module, L *layout) error {
	if err := binary.Write(w, binary.LittleEndian, uint32(len(ms))); err != nil {
		return err
	}
	for i, m := range ms {
		// MINIDUMP_MODULE = 108 bytes.
		if err := binary.Write(w, binary.LittleEndian, struct {
			BaseOfImage   uint64
			SizeOfImage   uint32
			CheckSum      uint32
			TimeDateStamp uint32
			ModuleNameRva uint32
			// VS_FIXEDFILEINFO (52 bytes): Signature+StrucVersion+6×u32+
			// FileFlagsMask+FileFlags+FileOS+FileType+FileSubtype+
			// FileDateMS+FileDateLS = 13 × u32.
			VersionInfo [13]uint32
			// MINIDUMP_LOCATION_DESCRIPTOR CvRecord (8) + MiscRecord (8)
			CvRecordSize uint32
			CvRecordRva  uint32
			MiscSize     uint32
			MiscRva      uint32
			Reserved0    uint64
			Reserved1    uint64
		}{
			BaseOfImage:   m.BaseOfImage,
			SizeOfImage:   m.SizeOfImage,
			CheckSum:      m.CheckSum,
			TimeDateStamp: m.TimeDateStamp,
			ModuleNameRva: L.moduleNameRvas[i],
		}); err != nil {
			return err
		}
	}
	// Emit MINIDUMP_STRINGs for each module name directly after the list.
	for _, m := range ms {
		if err := writeMinidumpString(w, m.Name); err != nil {
			return err
		}
	}
	return nil
}

func writeMemory64List(w io.Writer, rs []MemoryRegion, L *layout) error {
	if err := binary.Write(w, binary.LittleEndian, struct {
		NumberOfMemoryRanges uint64
		BaseRva              uint64
	}{
		NumberOfMemoryRanges: uint64(len(rs)),
		BaseRva:              L.memory64BaseRva,
	}); err != nil {
		return err
	}
	for _, r := range rs {
		if err := binary.Write(w, binary.LittleEndian, struct {
			StartOfMemoryRange uint64
			DataSize           uint64
		}{
			StartOfMemoryRange: r.BaseAddress,
			DataSize:           uint64(len(r.Data)),
		}); err != nil {
			return err
		}
	}
	// Raw region bytes packed after the descriptor array.
	for _, r := range rs {
		if _, err := w.Write(r.Data); err != nil {
			return err
		}
	}
	return nil
}
