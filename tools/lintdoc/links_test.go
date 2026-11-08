package main

import (
	"slices"
	"testing"
)

func TestBlankCodeSpans(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{line: "plain", want: "plain"},
		{line: "a `b` c", want: "a     c"},
		{line: "``a`b`` c", want: "        c"},
		{line: "open ` only", want: "open ` only"},
		{line: "``a` x", want: "``a` x"},
		{line: "`x` and `[y](z)`", want: "    and         "},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			if got := blankCodeSpans(tt.line); got != tt.want {
				t.Fatalf("blankCodeSpans(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestHasScheme(t *testing.T) {
	tests := []struct {
		target string
		want   bool
	}{
		{target: "https://example.com", want: true},
		{target: "mailto:a@example.com", want: true},
		{target: "git+ssh://example.com", want: true},
		{target: "a.b-c+d:x", want: true},
		{target: "docs/x.md", want: false},
		{target: ":x", want: false},
		{target: "1a:x", want: false},
		{target: "a/b:c", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			if got := hasScheme(tt.target); got != tt.want {
				t.Fatalf("hasScheme(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestMarkdownLinks(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []link
	}{
		{name: "none", content: "plain text\n"},
		{name: "inline", content: "see [a](b.md).\n", want: []link{{target: "b.md", off: 8}}},
		{name: "image", content: "![a](b.png)\n", want: []link{{target: "b.png", off: 5}}},
		{name: "title", content: "[a](b.md \"t\")\n", want: []link{{target: "b.md", off: 4}}},
		{name: "angle", content: "[a](<b c.md>)\n", want: []link{{target: "b c.md", off: 4}}},
		{name: "open angle", content: "[a](<b\n", want: []link{{target: "", off: 4}}},
		{name: "end of line", content: "[a](b.md", want: []link{{target: "b.md", off: 4}}},
		{name: "two on a line", content: "[a](b) [c](d)\n", want: []link{{target: "b", off: 4}, {target: "d", off: 11}}},
		{name: "second line", content: "x\n[a](b)\n", want: []link{{target: "b", off: 6}}},
		{name: "code span", content: "`[a](b)` [c](d)\n", want: []link{{target: "d", off: 13}}},
		{name: "backtick fence", content: "```text\n[a](b)\n```\n[c](d)\n", want: []link{{target: "d", off: 23}}},
		{name: "tilde fence", content: "  ~~~\n[a](b)\n~~~\n", want: nil},
		{name: "reference definition", content: "  [a]: b.md \"t\"\n", want: []link{{target: "b.md", off: 7}}},
		{name: "reference without space", content: "[a]:b.md\n"},
		{name: "reference without label", content: "[]: b.md\n"},
		{name: "reference without colon", content: "[a] b.md\n"},
		{name: "reference without bracket", content: "[a: b.md\n"},
		{name: "reference without target", content: "[a]: \n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := markdownLinks([]byte(tt.content)); !slices.Equal(got, tt.want) {
				t.Fatalf("markdownLinks(%q) = %v, want %v", tt.content, got, tt.want)
			}
		})
	}
}

func TestCheckLinks(t *testing.T) {
	g, dir := tempGate(t)
	writeFile(t, dir, "README.md", "[a](docs/a.md) [web](https://example.com/x.md)\n")
	writeFile(t, dir, "notes.txt", "[gone](gone.md)\n")
	writeFile(t, dir, "up.png", "")
	writeFile(t, dir, "docs/b.md", "")
	writeFile(t, dir, "docs/sub/c.md", "")
	writeFile(t, dir, "docs/a.md", "[ok](b.md) [dir](sub/) [frag](b.md#x) [self](#top)\n"+
		"[gone](missing.md)\n"+
		"![img](../up.png)\n"+
		"`[span](span.md)` [out](../../x.md)\n"+
		"[abs](/docs/b.md)\n"+
		"\n"+
		"```text\n"+
		"[fenced](fenced.md)\n"+
		"```\n"+
		"\n"+
		"[ref]: ref-missing.md\n")
	if err := g.checkLinks(); err != nil {
		t.Fatalf("checkLinks: %v", err)
	}
	want := []string{
		"docs/a.md:11:8: " + deadLinkMessage,
		"docs/a.md:2:8: " + deadLinkMessage,
		"docs/a.md:4:25: " + outsideLinkMessage,
		"docs/a.md:5:7: " + absoluteLinkMessage,
	}
	got := slices.Sorted(slices.Values(g.found))
	if !slices.Equal(got, want) {
		t.Fatalf("findings = %q, want %q", got, want)
	}
}
