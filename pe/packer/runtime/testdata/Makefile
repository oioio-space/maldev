# Reproducible rebuild of the Stage C+D test fixture.
# Run from this directory: `make` or `make hello_static_pie`.

GO ?= go

hello_static_pie: hello_static_pie.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -buildmode=pie \
		-ldflags='-s -w' \
		-o $@ ./$<

clean:
	rm -f hello_static_pie

.PHONY: clean
