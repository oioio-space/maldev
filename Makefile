# maldev build pipeline
# Usage:
#   make build          # standard build (development)
#   make release        # OPSEC build (garble + strip + trimpath)
#   make test           # run all tests
#   make test-intrusive # run intrusive tests (shellcode execution)
#   make cross-linux    # cross-compile for Linux amd64

BINARY   ?= implant.exe
CMD      ?= ./cmd/rshell
GOFLAGS  := -trimpath
LDFLAGS  := -s -w -H windowsgui -buildid=
TAGS     ?=

# Standard development build
.PHONY: build
build:
	go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY) $(CMD)

# OPSEC release build (requires: go install mvdan.cc/garble@latest)
# - garble: randomizes symbols, encrypts strings, strips pclntab info
# - -literals: encrypts all string literals in the binary
# - -tiny: removes extra runtime info (panic messages, print support)
# - -seed=random: different obfuscation per build
.PHONY: release
release:
	CGO_ENABLED=0 garble -literals -tiny -seed=random \
		build $(GOFLAGS) -ldflags="$(LDFLAGS)" -tags="$(TAGS)" \
		-o $(BINARY) $(CMD)

# Debug build (with logging enabled)
.PHONY: debug
debug:
	go build $(GOFLAGS) -tags=debug -ldflags="-s -w" -o $(BINARY) $(CMD)

# Run all tests (non-intrusive)
.PHONY: test
test:
	go test $$(go list ./... | grep -v /ignore) -count=1

# Run intrusive tests (requires MALDEV_INTRUSIVE=1)
.PHONY: test-intrusive
test-intrusive:
	MALDEV_INTRUSIVE=1 go test $$(go list ./... | grep -v /ignore) -count=1

# Cross-compile for Linux
.PHONY: cross-linux
cross-linux:
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags="-s -w" -o implant_linux $(CMD)

# Build all packages (verification)
.PHONY: verify
verify:
	go build $$(go list ./... | grep -v /ignore)
	go test $$(go list ./... | grep -v /ignore) -count=1
	GOOS=linux GOARCH=amd64 go build $$(go list ./... | grep -v /ignore)
	@echo "All checks passed."

# Install garble
.PHONY: install-garble
install-garble:
	go install mvdan.cc/garble@latest

# Clean
.PHONY: clean
clean:
	rm -f $(BINARY) implant_linux *.exe
