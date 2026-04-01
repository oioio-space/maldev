module github.com/oioio-space/maldev/c2

go 1.20

require (
	github.com/creack/pty v1.1.24
	github.com/ebitengine/purego v0.8.2
	github.com/oioio-space/maldev/injection v0.0.0
	github.com/oioio-space/maldev/win v0.0.0
	golang.org/x/sys v0.30.0
)

replace (
	github.com/oioio-space/maldev/injection => ../injection
	github.com/oioio-space/maldev/win => ../win
)
