module github.com/oioio-space/maldev/pe

go 1.21

require (
	github.com/oioio-space/maldev/core v0.0.0
	github.com/saferwall/pe v1.5.6
)

require (
	github.com/edsrzf/mmap-go v1.1.0 // indirect
	github.com/secDre4mer/pkcs7 v0.0.0-20240322103146-665324a4461d // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)

replace github.com/oioio-space/maldev/core => ../core
