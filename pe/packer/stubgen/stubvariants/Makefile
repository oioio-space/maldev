# Reproducible rebuild of the Phase 1e-A stage-2 stub variants.
# Run from this directory: `make all` or `make stage2_v01.exe`.
#
# Build flags:
#   -trimpath   removes all local path prefixes from debug info
#   -s -w       strip symbol table + DWARF (shrinks binary ~30 %)
#   -buildid='' zeroes the build-ID so byte output is stable across
#               separate rebuilds of the same source + toolchain

GO ?= go

# v01: baseline build.  Future v02 / v03 variants will tweak ldflags or
# inject minor source variants for additional per-pack byte diversity.
stage2_v01.exe: stage2_main.go
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		$(GO) build -trimpath \
		-ldflags='-s -w -buildid=' \
		-o $@ ./$<

all: stage2_v01.exe

clean:
	rm -f stage2_v01.exe

.PHONY: all clean
