#!/usr/bin/env bash
# Rebuild pe/packer/testdata/winhello_w32_res.exe — winhello_w32 with
# embedded RT_GROUP_ICON + RT_MANIFEST resources via tc-hib/winres
# (pure-Go, no mingw windres needed). Used by the resource-preservation
# E2E tests + by ignore/embed_resources.go (the throwaway driver this
# was promoted from).
set -euo pipefail
cd "$(dirname "$0")/.."
go run scripts/build-fixture-winres.go
