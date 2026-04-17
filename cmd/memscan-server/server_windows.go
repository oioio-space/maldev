package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type session struct {
	pid    uint32
	handle windows.Handle
}

type srv struct {
	mu       sync.Mutex
	sessions map[string]*session
}

func run(addr string) error {
	s := &srv{sessions: make(map[string]*session)}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/attach", s.attach)
	mux.HandleFunc("/detach", s.detach)
	mux.HandleFunc("/module", s.module)
	mux.HandleFunc("/export", s.export)
	mux.HandleFunc("/read", s.read)
	mux.HandleFunc("/find", s.find)
	fmt.Printf("memscan-server listening on %s\n", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *srv) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true})
}

type attachReq struct {
	PID uint32 `json:"pid"`
}

// attach opens the target with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ —
// enough for EnumProcessModules + ReadProcessMemory. No PROCESS_VM_WRITE: the
// server is read-only by design.
func (s *srv) attach(w http.ResponseWriter, r *http.Request) {
	var req attachReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.PID == 0 {
		writeErr(w, 400, errors.New("missing pid"))
		return
	}
	const rights = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
	h, err := windows.OpenProcess(rights, false, req.PID)
	if err != nil {
		writeErr(w, 500, fmt.Errorf("OpenProcess(%d): %w", req.PID, err))
		return
	}
	id := newSessionID()
	s.mu.Lock()
	s.sessions[id] = &session{pid: req.PID, handle: h}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"session": id, "pid": req.PID})
}

type detachReq struct {
	Session string `json:"session"`
}

func (s *srv) detach(w http.ResponseWriter, r *http.Request) {
	var req detachReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	s.mu.Lock()
	sess, ok := s.sessions[req.Session]
	if ok {
		delete(s.sessions, req.Session)
	}
	s.mu.Unlock()
	if !ok {
		writeErr(w, 404, errors.New("unknown session"))
		return
	}
	// CloseHandle returns BOOL; non-zero = success. Log but don't fail the
	// request — the session is already removed from the map.
	if err := windows.CloseHandle(sess.handle); err != nil {
		fmt.Fprintf(w, "warn: CloseHandle: %v\n", err)
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

type moduleReq struct {
	Session string `json:"session"`
	Name    string `json:"name"`
}

// module enumerates modules in the target and returns the base+size of the
// one whose filename matches (case-insensitive).
func (s *srv) module(w http.ResponseWriter, r *http.Request) {
	var req moduleReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	sess, err := s.getSession(req.Session)
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	base, size, err := findModule(sess.handle, req.Name)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"base": fmt.Sprintf("0x%x", base),
		"size": size,
	})
}

type exportReq struct {
	Session string `json:"session"`
	Module  string `json:"module"` // hex base, e.g. "0x7ff812340000"
	Name    string `json:"name"`
}

// export resolves a module export address using the server-process local
// copy of the module. Safe for system DLLs (ntdll, kernel32, user32) which
// share the same base across all processes in the same boot session —
// sufficient for the Phase 1 SSN verification matrix. A future version will
// walk the target's remote PE header for user DLLs and split-ASLR edge cases.
func (s *srv) export(w http.ResponseWriter, r *http.Request) {
	var req exportReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	// Resolve the module name from its remote base so we know which local
	// DLL to call GetProcAddress on.
	sess, err := s.getSession(req.Session)
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	modBase, err := parseHex(req.Module)
	if err != nil {
		writeErr(w, 400, fmt.Errorf("parse module: %w", err))
		return
	}
	name, err := moduleNameAt(sess.handle, modBase)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	addr, err := localExport(name, req.Name)
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	writeJSON(w, 200, map[string]any{"addr": fmt.Sprintf("0x%x", addr)})
}

type readReq struct {
	Session string `json:"session"`
	Addr    string `json:"addr"` // hex
	Size    uint32 `json:"size"`
}

func (s *srv) read(w http.ResponseWriter, r *http.Request) {
	var req readReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.Size == 0 || req.Size > 1<<20 {
		writeErr(w, 400, fmt.Errorf("size out of range: %d (max 1 MiB)", req.Size))
		return
	}
	sess, err := s.getSession(req.Session)
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	addr, err := parseHex(req.Addr)
	if err != nil {
		writeErr(w, 400, fmt.Errorf("parse addr: %w", err))
		return
	}
	buf := make([]byte, req.Size)
	var n uintptr
	if err := windows.ReadProcessMemory(sess.handle, addr, &buf[0], uintptr(req.Size), &n); err != nil {
		writeErr(w, 500, fmt.Errorf("ReadProcessMemory @0x%x size=%d: %w", addr, req.Size, err))
		return
	}
	writeJSON(w, 200, map[string]any{
		"addr": fmt.Sprintf("0x%x", addr),
		"read": uint32(n),
		"data": base64.StdEncoding.EncodeToString(buf[:n]),
	})
}

type findReq struct {
	Session    string `json:"session"`
	PatternHex string `json:"pattern_hex"`
	Regions    string `json:"regions"` // "rx" | "rwx" | "any" (default "any")
	MaxHits    int    `json:"max_hits"`
}

// find walks VirtualQueryEx across the user-space range, reads committed
// regions whose protection matches the filter, and scans for the given
// byte pattern. Returns up to max_hits matching addresses (default 64).
func (s *srv) find(w http.ResponseWriter, r *http.Request) {
	var req findReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.MaxHits <= 0 || req.MaxHits > 1024 {
		req.MaxHits = 64
	}
	pat, err := hex.DecodeString(strings.ReplaceAll(req.PatternHex, " ", ""))
	if err != nil {
		writeErr(w, 400, fmt.Errorf("pattern_hex: %w", err))
		return
	}
	if len(pat) == 0 || len(pat) > 4096 {
		writeErr(w, 400, fmt.Errorf("pattern length out of range: %d", len(pat)))
		return
	}
	sess, err := s.getSession(req.Session)
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	matches, err := scanProcess(sess.handle, pat, req.Regions, req.MaxHits)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	hexAddrs := make([]string, len(matches))
	for i, m := range matches {
		hexAddrs[i] = fmt.Sprintf("0x%x", m)
	}
	writeJSON(w, 200, map[string]any{
		"matches": hexAddrs,
		"count":   len(hexAddrs),
	})
}

// scanProcess walks the target's address space via VirtualQueryEx, reads
// committed regions matching the protection filter, and locates `pat`.
// Stops at maxHits. Caps total scanned bytes at 256 MiB to keep a large
// process from hanging the server.
func scanProcess(h windows.Handle, pat []byte, filter string, maxHits int) ([]uintptr, error) {
	const (
		userSpaceMax = uintptr(0x7FFF_FFFF_FFFF) // x64 user-mode ceiling
		maxScan      = 256 * 1024 * 1024         // 256 MiB safety cap
		chunkSize    = 4 * 1024 * 1024           // 4 MiB per ReadProcessMemory call
	)
	var (
		addr    uintptr
		scanned int
		out     []uintptr
	)
	buf := make([]byte, chunkSize)
	for addr < userSpaceMax && scanned < maxScan && len(out) < maxHits {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		if mbi.RegionSize == 0 {
			break
		}
		if mbi.State == windows.MEM_COMMIT && protectionMatches(mbi.Protect, filter) {
			region := uintptr(mbi.RegionSize)
			base := addr
			for off := uintptr(0); off < region && len(out) < maxHits; off += chunkSize {
				remaining := region - off
				if remaining > chunkSize {
					remaining = chunkSize
				}
				scanned += int(remaining)
				if scanned > maxScan {
					remaining -= uintptr(scanned - maxScan)
					if remaining == 0 {
						break
					}
				}
				var n uintptr
				if err := windows.ReadProcessMemory(h, base+off, &buf[0], remaining, &n); err != nil {
					continue // unreadable page (guard, no-access) — skip
				}
				// Pattern is typically a 16-byte ASCII marker.
				region := buf[:n]
				searchStart := 0
				for {
					i := bytes.Index(region[searchStart:], pat)
					if i < 0 {
						break
					}
					out = append(out, base+off+uintptr(searchStart+i))
					if len(out) >= maxHits {
						break
					}
					searchStart += i + 1
				}
			}
		}
		addr = uintptr(mbi.BaseAddress) + uintptr(mbi.RegionSize)
	}
	return out, nil
}

// protectionMatches reports whether Protect flags satisfy the filter.
// "rx"  = PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE (executable, readable)
// "rwx" = PAGE_EXECUTE_READWRITE only
// "any" = any readable region (default)
func protectionMatches(protect uint32, filter string) bool {
	const (
		pageExecRead    = 0x20 // PAGE_EXECUTE_READ
		pageExecReadWr  = 0x40 // PAGE_EXECUTE_READWRITE
		pageReadable    = 0x02 | 0x04 | 0x20 | 0x40 | 0x80
	)
	switch strings.ToLower(filter) {
	case "rwx":
		return protect&pageExecReadWr != 0
	case "rx":
		return protect&(pageExecRead|pageExecReadWr) != 0
	default: // "any" / ""
		return protect&pageReadable != 0
	}
}

func (s *srv) getSession(id string) (*session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("unknown session %q", id)
	}
	return sess, nil
}

// enumModules returns every module handle in the target via EnumProcessModulesEx
// (LIST_MODULES_ALL). Two calls: probe for needed bytes, then fetch.
func enumModules(h windows.Handle) ([]windows.Handle, error) {
	var needed uint32
	if err := windows.EnumProcessModulesEx(h, nil, 0, &needed, windows.LIST_MODULES_ALL); err != nil {
		return nil, fmt.Errorf("EnumProcessModulesEx probe: %w", err)
	}
	count := int(needed) / int(unsafe.Sizeof(windows.Handle(0)))
	mods := make([]windows.Handle, count)
	if err := windows.EnumProcessModulesEx(h, &mods[0], needed, &needed, windows.LIST_MODULES_ALL); err != nil {
		return nil, fmt.Errorf("EnumProcessModulesEx fetch: %w", err)
	}
	return mods, nil
}

// moduleBasename returns the lowercase basename of module m loaded in h.
func moduleBasename(h, m windows.Handle) (string, error) {
	var path [windows.MAX_PATH]uint16
	if err := windows.GetModuleFileNameEx(h, m, &path[0], windows.MAX_PATH); err != nil {
		return "", err
	}
	return basename(strings.ToLower(windows.UTF16ToString(path[:]))), nil
}

// findModule returns base+size for the first module whose basename matches
// `name` (case-insensitive — "ntdll.dll" matches "C:\...\ntdll.dll").
func findModule(h windows.Handle, name string) (base uintptr, size uint32, err error) {
	mods, err := enumModules(h)
	if err != nil {
		return 0, 0, err
	}
	want := strings.ToLower(name)
	for _, m := range mods {
		got, err := moduleBasename(h, m)
		if err != nil {
			continue
		}
		if got == want {
			var info windows.ModuleInfo
			if err := windows.GetModuleInformation(h, m, &info, uint32(unsafe.Sizeof(info))); err != nil {
				return 0, 0, fmt.Errorf("GetModuleInformation: %w", err)
			}
			return info.BaseOfDll, info.SizeOfImage, nil
		}
	}
	return 0, 0, fmt.Errorf("module %q not loaded in target", name)
}

// moduleNameAt reverse-looks-up a remote base address to a module basename.
// Used by /export to decide which local DLL to resolve exports against.
func moduleNameAt(h windows.Handle, base uintptr) (string, error) {
	mods, err := enumModules(h)
	if err != nil {
		return "", err
	}
	for _, m := range mods {
		if uintptr(m) != base {
			continue
		}
		name, err := moduleBasename(h, m)
		if err != nil {
			continue
		}
		return name, nil
	}
	return "", fmt.Errorf("no module at base 0x%x", base)
}

// localExport resolves an export in the SERVER process's own loaded copy of
// module `modName` (e.g., "ntdll.dll"). Only valid for system DLLs shared
// across all processes.
func localExport(modName, export string) (uintptr, error) {
	mod, err := windows.LoadLibrary(modName)
	if err != nil {
		return 0, fmt.Errorf("LoadLibrary %s: %w", modName, err)
	}
	// Don't FreeLibrary — system DLLs are always loaded, refcount is fine.
	addr, err := windows.GetProcAddress(mod, export)
	if err != nil {
		return 0, fmt.Errorf("GetProcAddress %s!%s: %w", modName, export, err)
	}
	return addr, nil
}

func basename(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func parseHex(s string) (uintptr, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	n, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, err
	}
	return uintptr(n), nil
}

func newSessionID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func readJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(dst)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
