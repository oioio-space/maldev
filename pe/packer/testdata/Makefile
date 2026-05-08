# Builds the Windows PE fixture used by
# TestPackBinary_WindowsPE_PackTimeMultiSeed. Cross-build only —
# nothing here runs on Windows.

.PHONY: all winhello clean

all: winhello

winhello: winhello.exe

winhello.exe: winhello.go
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		go build -ldflags='-s -w' -o $@ ./winhello.go

clean:
	rm -f winhello.exe
