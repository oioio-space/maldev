module github.com/oioio-space/maldev/process

go 1.20

require (
	github.com/mitchellh/go-ps v1.0.0
	github.com/oioio-space/maldev/win v0.0.0
	golang.org/x/sys v0.30.0
)

replace github.com/oioio-space/maldev/win => ../win
