module github.com/oioio-space/maldev/privilege

go 1.21

require (
	github.com/oioio-space/maldev/core v0.0.0
	github.com/oioio-space/maldev/win v0.0.0
	golang.org/x/sys v0.30.0
)

replace (
	github.com/oioio-space/maldev/core => ../core
	github.com/oioio-space/maldev/win => ../win
)
