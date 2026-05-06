package donors

// Donor associates a Go-identifier-safe ID (used as preset
// sub-package name + cert blob filename stem) with the on-disk
// path to the donor PE.
type Donor struct {
	ID   string
	Path string
}

// All is the canonical donor list. New entries here join both
// the .syso generation flow (pe/masquerade/internal/gen) and the
// cert-snapshot flow (cmd/cert-snapshot) without further wiring.
//
// Per-host availability varies — both consumers SKIP-on-stat so
// the slice can list more donors than any single dev box has.
var All = []Donor{
	{"cmd", `${SystemRoot}\System32\cmd.exe`},
	{"svchost", `${SystemRoot}\System32\svchost.exe`},
	{"taskmgr", `${SystemRoot}\System32\taskmgr.exe`},
	{"explorer", `${SystemRoot}\explorer.exe`},
	{"notepad", `${SystemRoot}\System32\notepad.exe`},
	{"msedge", `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`},
	{"onedrive", `${LOCALAPPDATA}\Microsoft\OneDrive\OneDrive.exe`},
	{"wt", `${LOCALAPPDATA}\Microsoft\WindowsApps\wt.exe`},
	{"acrobat", `${ProgramFiles}\Adobe\Acrobat DC\Acrobat\Acrobat.exe`},
	{"firefox", `${ProgramFiles}\Mozilla Firefox\firefox.exe`},
	{"excel", `${ProgramFiles}\Microsoft Office\root\Office16\EXCEL.EXE`},
	{"sevenzip", `${ProgramFiles}\7-Zip\7zFM.exe`},
	{"vscode", `${LOCALAPPDATA}\Programs\Microsoft VS Code\Code.exe`},
	{"claude", `${LOCALAPPDATA}\AnthropicClaude\claude.exe`},
}
