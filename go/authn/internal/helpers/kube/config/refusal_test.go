package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Refusals must list every Refusal constant declared in this package: a caller
// proves its own map complete against it (the audit record's denial reason), so
// a constant missing from the list would escape that proof. The set is read
// from the source, not from the list under test.
func TestRefusalsListsEveryRefusal(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	require.NoError(t, err)
	var declared []string
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if len(name) > 8 && name[len(name)-8:] == "_test.go" {
				continue
			}
			for _, d := range file.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Refusal" {
						continue
					}
					for _, v := range vs.Values {
						lit, ok := v.(*ast.BasicLit)
						require.True(t, ok, "a Refusal constant must be a string literal")
						s, err := strconv.Unquote(lit.Value)
						require.NoError(t, err)
						declared = append(declared, s)
					}
				}
			}
		}
	}
	listed := make([]string, len(Refusals))
	for i, r := range Refusals {
		listed[i] = string(r)
	}
	sort.Strings(declared)
	sort.Strings(listed)
	require.NotEmpty(t, declared, "the scan found no Refusal constants")
	assert.Equal(t, declared, listed, "Refusals must list exactly the declared Refusal constants")
}
