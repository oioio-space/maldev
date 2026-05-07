# Reproducible rebuild of the Phase 1e-A/B stage-2 stub variants.
# Run from this directory: `make all` builds both variants.
#
# Build flags:
#   -trimpath   removes all local path prefixes from debug info
#   -s -w       strip symbol table + DWARF (shrinks binary ~30 %)
#   -buildid='' zeroes the build-ID so byte output is stable across
#               separate rebuilds of the same source + toolchain

GO ?= go

# Phase 1e-A: Windows EXE (stage 2 wraps the Windows runtime path)
stage2_v01.exe: stage2_main.go
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		$(GO) build -trimpath \
		-ldflags='-s -w -buildid=' \
		-o $@ ./$<

# Phase 1e-B: Linux ELF static-PIE (stage 2 wraps the Linux runtime
# path — Phase 1f Stage E). -buildmode=pie produces ET_DYN with the
# right section layout (RELA entries kept; -d would drop them and
# break .data.rel.ro pointers).
stage2_linux_v01: stage2_main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -trimpath \
		-buildmode=pie \
		-ldflags='-s -w -buildid=' \
		-o $@ ./$<

all: stage2_v01.exe stage2_linux_v01

clean:
	rm -f stage2_v01.exe stage2_linux_v01

.PHONY: all clean
