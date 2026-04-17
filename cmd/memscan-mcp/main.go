// Command memscan-mcp is a minimal Model Context Protocol adapter that
// exposes the memscan-server HTTP API as MCP tools over stdio JSON-RPC 2.0.
//
// Claude Code launches this process, talks to it on stdin/stdout, and the
// process relays each tool call to the memscan-server running inside the
// Windows VM. Tools available: read_memory, find_pattern, get_module,
// get_export. Each auto-attaches/detaches — Claude doesn't juggle sessions.
//
// Wire up via .mcp.json at repo root:
//
//	{
//	  "mcpServers": {
//	    "memscan": {
//	      "command": "go",
//	      "args": ["run", "./cmd/memscan-mcp",
//	               "--server", "http://192.168.122.122:50300"]
//	    }
//	  }
//	}
//
// Cross-platform (pure Go HTTP client + stdio). Safe to run on Linux host
// against a Windows VM memscan-server.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const protocolVersion = "2024-11-05"

var (
	serverURL string
	logger    = log{w: os.Stderr}
)

func main() {
	flag.StringVar(&serverURL, "server", "http://127.0.0.1:50300", "memscan-server base URL")
	flag.Parse()

	r := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	var mu sync.Mutex

	for {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			return
		}
		if err != nil {
			logger.Printf("stdin read: %v", err)
			return
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			logger.Printf("parse request: %v", err)
			continue
		}
		resp := dispatch(&req)
		if resp == nil {
			// Notification: no response.
			continue
		}
		buf, _ := json.Marshal(resp)
		mu.Lock()
		_, _ = w.Write(buf)
		_, _ = w.WriteString("\n")
		_ = w.Flush()
		mu.Unlock()
	}
}

// -------------------------------------------------------------------
// JSON-RPC 2.0 wire types

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func ok(id json.RawMessage, result any) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func fail(id json.RawMessage, code int, msg string) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// -------------------------------------------------------------------
// MCP dispatch

func dispatch(req *rpcRequest) *rpcResponse {
	// Notifications (no ID) expect no response.
	isNotification := len(req.ID) == 0
	switch req.Method {
	case "initialize":
		return ok(req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "memscan", "version": "0.1.0"},
		})
	case "notifications/initialized", "notifications/cancelled":
		return nil // notification, no response
	case "ping":
		return ok(req.ID, map[string]any{})
	case "tools/list":
		return ok(req.ID, map[string]any{"tools": toolDefs()})
	case "tools/call":
		return callTool(req)
	default:
		if isNotification {
			return nil
		}
		return fail(req.ID, -32601, "method not found: "+req.Method)
	}
}

func toolDefs() []map[string]any {
	return []map[string]any{
		{
			"name":        "run_tests",
			"description": "Run the maldev test suite inside the VMs and return the full report. layer = memscan (~2 min, 77-row byte-pattern matrix), linux (~3-5 min, go test ./... in Ubuntu VM with MALDEV_INTRUSIVE+MANUAL), windows (~5-10 min, Windows VM), all (runs sequentially, ~15 min). Reproducible via scripts/test-all.sh.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"layer": map[string]any{
						"type":    "string",
						"enum":    []string{"memscan", "linux", "windows", "all"},
						"default": "memscan",
					},
					"packages": map[string]any{
						"type":        "string",
						"description": "optional — restrict go test to a package glob, e.g. ./c2/shell/...",
					},
				},
			},
		},
		{
			"name":        "read_memory",
			"description": "Read bytes from a Windows process via ReadProcessMemory. Returns base64-encoded data.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pid":  map[string]any{"type": "integer"},
					"addr": map[string]any{"type": "string", "description": "hex address e.g. 0x7fff..."},
					"size": map[string]any{"type": "integer", "description": "bytes to read (≤ 1 MiB)"},
				},
				"required": []string{"pid", "addr", "size"},
			},
		},
		{
			"name":        "find_pattern",
			"description": "Scan a Windows process for a byte pattern across committed regions. Returns matching addresses.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pid":         map[string]any{"type": "integer"},
					"pattern_hex": map[string]any{"type": "string", "description": "hex bytes, spaces allowed"},
					"regions":     map[string]any{"type": "string", "enum": []string{"rx", "rwx", "any"}, "default": "any"},
					"max_hits":    map[string]any{"type": "integer", "default": 64},
				},
				"required": []string{"pid", "pattern_hex"},
			},
		},
		{
			"name":        "get_module",
			"description": "Return the base address and size of a loaded module (e.g. ntdll.dll) in a Windows process.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pid":  map[string]any{"type": "integer"},
					"name": map[string]any{"type": "string"},
				},
				"required": []string{"pid", "name"},
			},
		},
		{
			"name":        "get_export",
			"description": "Resolve an exported function's address in a loaded module of a Windows process.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pid":    map[string]any{"type": "integer"},
					"module": map[string]any{"type": "string", "description": "e.g. ntdll.dll"},
					"name":   map[string]any{"type": "string", "description": "e.g. NtAllocateVirtualMemory"},
				},
				"required": []string{"pid", "module", "name"},
			},
		},
	}
}

// callTool wraps the HTTP API with an implicit session lifecycle so Claude
// calls look atomic: attach → op → detach on every tool invocation.
func callTool(req *rpcRequest) *rpcResponse {
	var p struct {
		Name      string                 `json:"name"`
		Arguments map[string]any         `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return fail(req.ID, -32602, "parse params: "+err.Error())
	}
	// run_tests is a non-session tool: it shells out to test-all.sh and
	// doesn't need memscan-server. Dispatch early, before attach.
	if p.Name == "run_tests" {
		text, callErr := opRunTests(p.Arguments)
		if callErr != nil {
			return ok(req.ID, map[string]any{
				"content": []map[string]any{{"type": "text", "text": callErr.Error() + "\n\n" + text}},
				"isError": true,
			})
		}
		return ok(req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
		})
	}

	pid, err := asUint32(p.Arguments["pid"])
	if err != nil {
		return fail(req.ID, -32602, "pid: "+err.Error())
	}
	session, err := httpAttach(pid)
	if err != nil {
		return fail(req.ID, -32000, "attach: "+err.Error())
	}
	defer func() { _ = httpDetach(session) }()

	var text string
	var callErr error
	switch p.Name {
	case "read_memory":
		text, callErr = opReadMemory(session, p.Arguments)
	case "find_pattern":
		text, callErr = opFindPattern(session, p.Arguments)
	case "get_module":
		text, callErr = opGetModule(session, p.Arguments)
	case "get_export":
		text, callErr = opGetExport(session, p.Arguments)
	default:
		return fail(req.ID, -32601, "unknown tool: "+p.Name)
	}
	if callErr != nil {
		// Return as a tool-level error: per MCP, `isError: true` in content.
		return ok(req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": callErr.Error()}},
			"isError": true,
		})
	}
	return ok(req.ID, map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
	})
}

// opRunTests shells out to scripts/test-all.sh. Long-running — Claude's
// tool-call UI stays in "running" state for the duration. Returns stdout
// and non-nil error iff the script exits non-zero.
func opRunTests(a map[string]any) (string, error) {
	layer, _ := a["layer"].(string)
	if layer == "" {
		layer = "memscan"
	}
	args := []string{"./scripts/test-all.sh", "--continue"}
	switch layer {
	case "memscan", "linux", "windows":
		args = append(args, "--only="+layer)
	case "all":
		// default behaviour — no --only flag
	default:
		return "", fmt.Errorf("unknown layer %q (want memscan|linux|windows|all)", layer)
	}
	if pkgs, ok := a["packages"].(string); ok && pkgs != "" {
		args = append(args, "--pkgs="+pkgs)
	}
	cmd := exec.Command("bash", args...)
	// Source the per-host kali-env.sh if present so MALDEV_KALI_* reach
	// go test via the vmtest env-forwarding path.
	cmd.Env = append(os.Environ(), "MALDEV_INTRUSIVE=1", "MALDEV_MANUAL=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func opReadMemory(session string, a map[string]any) (string, error) {
	addr, _ := a["addr"].(string)
	size, err := asUint32(a["size"])
	if err != nil {
		return "", err
	}
	raw, err := httpRaw("/read", map[string]any{"session": session, "addr": addr, "size": size})
	if err != nil {
		return "", err
	}
	return formatJSON(raw), nil
}

func opFindPattern(session string, a map[string]any) (string, error) {
	regions, _ := a["regions"].(string)
	if regions == "" {
		regions = "any"
	}
	maxHits, _ := asInt(a["max_hits"])
	if maxHits == 0 {
		maxHits = 64
	}
	pat, _ := a["pattern_hex"].(string)
	raw, err := httpRaw("/find", map[string]any{
		"session":     session,
		"pattern_hex": pat,
		"regions":     regions,
		"max_hits":    maxHits,
	})
	if err != nil {
		return "", err
	}
	return formatJSON(raw), nil
}

func opGetModule(session string, a map[string]any) (string, error) {
	name, _ := a["name"].(string)
	raw, err := httpRaw("/module", map[string]any{"session": session, "name": name})
	if err != nil {
		return "", err
	}
	return formatJSON(raw), nil
}

func opGetExport(session string, a map[string]any) (string, error) {
	module, _ := a["module"].(string)
	name, _ := a["name"].(string)
	raw, err := httpRaw("/export", map[string]any{
		"session": session, "module": module, "name": name,
	})
	if err != nil {
		return "", err
	}
	return formatJSON(raw), nil
}

// -------------------------------------------------------------------
// HTTP client against memscan-server

var httpClient = &http.Client{Timeout: 60 * time.Second}

func httpRaw(path string, body any) (map[string]any, error) {
	buf, _ := json.Marshal(body)
	resp, err := httpClient.Post(serverURL+path, "application/json", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(raw))
	}
	if resp.StatusCode != 200 {
		return out, fmt.Errorf("HTTP %d: %v", resp.StatusCode, out["error"])
	}
	return out, nil
}

func httpAttach(pid uint32) (string, error) {
	out, err := httpRaw("/attach", map[string]any{"pid": pid})
	if err != nil {
		return "", err
	}
	s, _ := out["session"].(string)
	if s == "" {
		return "", fmt.Errorf("no session in response")
	}
	return s, nil
}

func httpDetach(session string) error {
	_, err := httpRaw("/detach", map[string]any{"session": session})
	return err
}

// -------------------------------------------------------------------
// Helpers

func asUint32(v any) (uint32, error) {
	switch x := v.(type) {
	case float64:
		return uint32(x), nil
	case int:
		return uint32(x), nil
	case string:
		n, err := strconv.ParseUint(strings.TrimPrefix(x, "0x"), 0, 32)
		if err != nil {
			return 0, err
		}
		return uint32(n), nil
	}
	return 0, fmt.Errorf("expected number, got %T", v)
}

func asInt(v any) (int, error) {
	switch x := v.(type) {
	case float64:
		return int(x), nil
	case int:
		return x, nil
	case string:
		n, err := strconv.Atoi(x)
		return n, err
	}
	return 0, fmt.Errorf("expected number, got %T", v)
}

// formatJSON prettifies a JSON map so Claude's tool-result content is
// readable. If the map carries "data" (base64 from /read), it is kept as-is
// since Claude can decode it; an extra "data_preview" hex prefix is added
// for quick visual inspection.
func formatJSON(m map[string]any) string {
	if s, ok := m["data"].(string); ok {
		if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
			n := len(raw)
			if n > 32 {
				n = 32
			}
			preview := ""
			for i := 0; i < n; i++ {
				preview += fmt.Sprintf("%02X ", raw[i])
			}
			m["data_preview"] = strings.TrimSpace(preview)
		}
	}
	buf, _ := json.MarshalIndent(m, "", "  ")
	return string(buf)
}

// log is a minimal logger that writes one line per call to the underlying
// writer. Used for MCP diagnostic messages on stderr (Claude Code shows
// them in the server logs pane).
type log struct{ w io.Writer }

func (l log) Printf(format string, args ...any) {
	fmt.Fprintf(l.w, "memscan-mcp: "+format+"\n", args...)
}
