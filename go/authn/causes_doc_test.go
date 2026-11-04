package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// docs/api.md is the one complete list of failure causes: a client reads it
// to decide what to tell a person, and treats it as exhaustive. This test
// finds every CauseType constant declared in the source and fails if one is
// missing from that list, so a new cause can't ship undocumented.
func TestEveryCauseIsDocumented(t *testing.T) {
	api, err := os.ReadFile(filepath.Join("..", "..", "docs", "api.md"))
	require.NoError(t, err)

	causes := causeConstants(t, "internal")
	require.NotEmpty(t, causes)
	// The scan must see causes declared both ways: as status.CauseType in a
	// route package and as CauseType inside package status.
	assert.Contains(t, causes, "IssuerMismatch")
	assert.Contains(t, causes, "IssuanceFailed")

	for _, c := range causes {
		assert.Contains(t, string(api), "| `"+c+"` |", "cause %s is declared in the source but has no row in docs/api.md", c)
	}
}

// causeConstants returns the string value of every constant of type CauseType
// (or status.CauseType) declared in a non-test Go file under dir.
func causeConstants(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				if !isCauseType(vs.Type) {
					continue
				}
				for _, v := range vs.Values {
					lit, ok := v.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					s, err := strconv.Unquote(lit.Value)
					require.NoError(t, err)
					out = append(out, s)
				}
			}
		}
		return nil
	})
	require.NoError(t, err)
	return out
}

func isCauseType(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "CauseType"
	case *ast.SelectorExpr:
		return x.Sel.Name == "CauseType"
	}
	return false
}
