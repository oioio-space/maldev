// fakelib — a real Windows DLL with three named C exports.
//
// Built into the orchestrator binary (//go:embed) and dropped at
// runtime on the target VM as C:\Vulnerable\fakelib.dll. The
// orchestrator then PARSES this DLL's exports on the VM to discover
// what name list to mirror in the Mode-10 PackProxyDLL hijack DLL.
//
// Why a real DLL (vs. a synthetic forwarder): the user's E2E
// requirement is "look at the DLL present on the box, build a proxy
// from it" — that path needs an honest PE with executable code, not
// just an export-table forwarder shell.
//
// Build (host, requires mingw):
//
//	GOTMPDIR=$(pwd)/ignore/gotmp CGO_ENABLED=1 \
//	  GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
//	  go build -buildmode=c-shared -o ignore/privesc-e2e/fakelib.dll \
//	  ./cmd/privesc-e2e/fakelib
//
// GOTMPDIR avoids Defender flagging the c-shared build output in
// the system TEMP dir.
package main

import "C"

//export FakeInit
func FakeInit() C.int { return 0 }

//export FakeStep
func FakeStep(n C.int) C.int { return n + 1 }

//export FakeFinal
func FakeFinal() C.int { return 42 }

func main() {}
