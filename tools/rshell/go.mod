module rshell

go 1.20

require (
	github.com/creack/pty v1.1.24
	github.com/ebitengine/purego v0.8.2
	github.com/oioio-space/maldev/c2 v0.0.0
	github.com/oioio-space/maldev/injection v0.0.0
	github.com/oioio-space/maldev/win v0.0.0
	github.com/shirou/gopsutil/v3 v3.24.5
	golang.org/x/sys v0.30.0
)

replace (
	github.com/oioio-space/maldev/c2 => ../../c2
	github.com/oioio-space/maldev/injection => ../../injection
	github.com/oioio-space/maldev/win => ../../win
)
