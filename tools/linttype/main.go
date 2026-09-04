// Command linttype gates the Go-side type discipline of the strike tree and
// surveys it. One extractor traversal produces every fact; the gates select
// the kinds they own from it.
//
// Three gates run by default, through multichecker, so each reports under its
// own name and can be enabled separately:
//
//   - linttypeconv: a conversion of a strike named type sitting directly in a
//     call argument, outside the type's own defining package. CUE gives these
//     types their structure and Go adds behavior; a conversion is behavior, so
//     it is owned in one place. The same string(id) is fine as a named
//     assignment, a composite-literal field, a method body or a bare return.
//   - linttypeflow: a value detyped and retyped within one function, a named
//     scalar returned as a plain string, or a detyping that bypasses the
//     String() boundary its type owns.
//   - linttypestutter: an accessor x.<Noun>.<Noun>() whose receiver type is
//     named differently from the accessor. See
//     docs/ADR-048-contract-type-semantics.md.
//
// The -report mode takes a separate path: it emits the full type-flow survey
// as JSONL on stdout and always exits zero, and it records every fact kind,
// not just the gating ones. Prose reports render from that data.
package main

import (
	"encoding/json"
	"log"
	"os"

	"golang.org/x/tools/go/analysis/multichecker"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("linttype: ")
	if len(os.Args) > 1 && os.Args[1] == "-report" {
		survey(os.Args[2:])
		return
	}
	multichecker.Main(ConvOwnerAnalyzer, FlowAnalyzer, StutterAnalyzer)
}

// survey emits every fact the extractor produces, gating nothing. It keeps the
// go/packages loader rather than the analysis driver because the survey is a
// whole-tree JSONL dump, not a set of per-package diagnostics.
func survey(patterns []string) {
	if len(patterns) == 0 {
		log.Fatal("usage: linttype -report <package-pattern>...")
	}
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	facts, err := collect(dir, patterns)
	if err != nil {
		log.Fatal(err)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, f := range facts {
		if err := enc.Encode(f); err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("facts: %d", len(facts))
}
