// build-fixture-winres.go regenerates
// pe/packer/testdata/winhello_w32_res.exe — winhello_w32.exe with an
// RT_GROUP_ICON + RT_MANIFEST embedded via tc-hib/winres (pure Go, no
// mingw windres dependency). Used by the resource-preservation E2E
// tests in pe/packer/.
//
// Run from the repo root:
//
//	scripts/build-fixture-winres.sh    # convenience wrapper
//	go run scripts/build-fixture-winres.go
package main

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"os"

	"github.com/tc-hib/winres"
)

func main() {
	const (
		in  = "pe/packer/testdata/winhello_w32.exe"
		out = "pe/packer/testdata/winhello_w32_res.exe"
	)

	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			img.Set(x, y, color.RGBA{R: 255, A: 255})
		}
	}
	icon, err := winres.NewIconFromImages([]image.Image{img})
	if err != nil {
		fmt.Fprintf(os.Stderr, "build-fixture-winres: NewIconFromImages: %v\n", err)
		os.Exit(1)
	}

	src, err := os.ReadFile(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build-fixture-winres: read %s: %v\n", in, err)
		os.Exit(1)
	}
	rs, err := winres.LoadFromEXE(bytes.NewReader(src))
	if err != nil {
		// no existing resources — start with an empty set.
		rs = &winres.ResourceSet{}
	}
	if err := rs.SetIconTranslation(winres.Name("MAINICON"), 0x0409, icon); err != nil {
		fmt.Fprintf(os.Stderr, "build-fixture-winres: SetIconTranslation: %v\n", err)
		os.Exit(1)
	}
	manifest := []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="winres" version="1.0.0.0"/>
</assembly>`)
	if err := rs.Set(winres.RT_MANIFEST, winres.ID(1), 0x0409, manifest); err != nil {
		fmt.Fprintf(os.Stderr, "build-fixture-winres: Set RT_MANIFEST: %v\n", err)
		os.Exit(1)
	}

	outFile, err := os.Create(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build-fixture-winres: create %s: %v\n", out, err)
		os.Exit(1)
	}
	defer outFile.Close()
	if err := rs.WriteToEXE(outFile, bytes.NewReader(src)); err != nil {
		fmt.Fprintf(os.Stderr, "build-fixture-winres: WriteToEXE: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d bytes)\n", out, len(src))
}
