package imports

import (
	"debug/pe"
	"fmt"
	"io"
	"strings"
)

type Import struct {
	DLL      string
	Function string
}

func List(pePath string) ([]Import, error) {
	f, err := pe.Open(pePath)
	if err != nil { return nil, fmt.Errorf("open PE: %w", err) }
	defer f.Close()
	return parseImports(f)
}

func ListByDLL(pePath, dllName string) ([]Import, error) {
	all, err := List(pePath)
	if err != nil { return nil, err }
	var filtered []Import
	for _, imp := range all {
		if strings.EqualFold(imp.DLL, dllName) {
			filtered = append(filtered, imp)
		}
	}
	return filtered, nil
}

func FromReader(r io.ReaderAt) ([]Import, error) {
	f, err := pe.NewFile(r)
	if err != nil { return nil, fmt.Errorf("parse PE: %w", err) }
	defer f.Close()
	return parseImports(f)
}

func parseImports(f *pe.File) ([]Import, error) {
	syms, err := f.ImportedSymbols()
	if err != nil { return nil, fmt.Errorf("read imports: %w", err) }
	var imports []Import
	for _, sym := range syms {
		parts := strings.SplitN(sym, ":", 2)
		if len(parts) != 2 { continue }
		imports = append(imports, Import{DLL: parts[1], Function: parts[0]})
	}
	return imports, nil
}
