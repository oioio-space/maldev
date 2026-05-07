# Reproducible rebuild of the Linux runtime test fixtures.
# Run from this directory: `make` (builds both) or a target name.

GO  ?= go
CC  ?= gcc

all: hello_static_pie hello_static_pie_c

# Stage C+D fixture — Go static-PIE built with the internal linker
# (no -extldflags=-static, which would need glibc-static). Produces
# the canonical Go static-PIE shape: PT_INTERP present but unused,
# zero DT_NEEDED, RELA entries for .data.rel.ro pointer fixup.
hello_static_pie: hello_static_pie.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -buildmode=pie \
		-ldflags='-s -w' \
		-o $@ ./$<

# Stage E fixture — hand-rolled non-Go static-PIE. Pure syscall
# write+exit_group, no libc, no Go runtime. Validates that the
# broadened gate accepts ELFs without .go.buildinfo as long as
# they meet the structural contract (ET_DYN + no DT_NEEDED).
hello_static_pie_c: hello_static_pie_c.s
	$(CC) -static-pie -nostdlib -fno-asynchronous-unwind-tables \
		-o $@ ./$<

clean:
	rm -f hello_static_pie hello_static_pie_c

.PHONY: all clean
