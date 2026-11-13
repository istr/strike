package main

import (
	"path/filepath"
	"strings"
	"testing"

	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/parser"
)

func gateFile(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile("t.cue", src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f
}

func TestTierDirection(t *testing.T) {
	cases := []struct {
		name string
		pkg  string
		imp  string
		want bool // want a finding
	}{
		{"downward is legal", "attest", "github.com/istr/strike/contract/lane", false},
		{"upward is a violation", "lane", "github.com/istr/strike/contract/attest", true},
		{"sideways concept is a violation", "endpoint", "github.com/istr/strike/contract/record", true},
		{"intra-package is exempt", "lane", "github.com/istr/strike/contract/lane", false},
		{"crossval allowed lane", "crossval", "github.com/istr/strike/contract/lane", false},
		{"crossval allowed endpoint", "crossval", "github.com/istr/strike/contract/endpoint", false},
		{"crossval forbidden attest", "crossval", "github.com/istr/strike/contract/attest", true},
		{"trustlayers allowed record", "trustlayers", "github.com/istr/strike/contract/record", false},
		{"trustlayers forbidden lane", "trustlayers", "github.com/istr/strike/contract/lane", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "package " + tc.pkg + "\n\nimport \"" + tc.imp + "\"\n\nx: 1\n"
			got := appendImportFindings(nil, gateFile(t, src))
			if tc.want && len(got) == 0 {
				t.Fatalf("expected a tier-direction finding for %s importing %s", tc.pkg, tc.imp)
			}
			if !tc.want && len(got) != 0 {
				t.Fatalf("unexpected findings: %v", got)
			}
		})
	}
}

func TestRequiredListForm(t *testing.T) {
	src := `package p

a: [...string]
b: [string, ...string]
c?: [...string]
d: []
e: [string]
env: {[string]: string}
[string]: [...int]
`
	got := appendRequiredListFindings(nil, gateFile(t, src))
	if len(got) != 1 || !strings.Contains(got[0], `"a"`) {
		t.Fatalf("expected exactly one finding for field a, got: %v", got)
	}
}

func TestContractGates(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	synFindings, err := contractSyntaxFindings(root)
	if err != nil {
		t.Fatalf("contract syntax lint: %v", err)
	}
	gateFindings, err := contractGateFindings(root)
	if err != nil {
		t.Fatalf("contract gate lint: %v", err)
	}
	findings := append(synFindings, gateFindings...)
	if len(findings) != 0 {
		t.Errorf("contract lint findings at the tree root:\n%s",
			strings.Join(findings, "\n"))
	}
}
