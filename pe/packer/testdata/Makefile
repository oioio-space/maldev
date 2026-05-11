# Builds the Windows PE fixture used by
# TestPackBinary_WindowsPE_PackTimeMultiSeed. Cross-build only —
# nothing here runs on Windows.

.PHONY: all winhello winpanic winhello_w32 clean

all: winhello winpanic winhello_w32

winhello: winhello.exe

winhello.exe: winhello.go
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		go build -ldflags='-s -w' -o $@ ./winhello.go

# Phase 2-F-3-c-3 EXCEPTION-walker fixture: triggers a hardware
# nil-deref → Go VEH → RtlVirtualUnwind walks .pdata. Used by
# TestPackBinary_WindowsPE_Panic_RandomizeAll_E2E.
winpanic: winpanic.exe

winpanic.exe: winpanic.go
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		go build -ldflags='-s -w' -o $@ ./winpanic.go

# Phase 2-F-3-c coverage fixture: non-Go (mingw) Win32 binary
# WITHOUT C runtime, so PlanPE accepts it (default mingw with
# CRT injects TLS callbacks → transform.ErrTLSCallbacks).
# Used by TestPackBinary_WindowsPE_W32_*_E2E.
winhello_w32: winhello_w32.exe

winhello_w32.exe: winhello_w32.c
	x86_64-w64-mingw32-gcc -nostdlib -O2 -e main -Wl,--strip-all \
		-o $@ ./winhello_w32.c -lkernel32

clean:
	rm -f winhello.exe winpanic.exe winhello_w32.exe
