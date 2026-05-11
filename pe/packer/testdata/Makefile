# Builds the Windows PE fixture used by
# TestPackBinary_WindowsPE_PackTimeMultiSeed. Cross-build only —
# nothing here runs on Windows.

.PHONY: all winhello winpanic clean

all: winhello winpanic

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

clean:
	rm -f winhello.exe winpanic.exe
