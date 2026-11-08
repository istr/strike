package main

import (
	"go/token"
	"io/fs"
	"path"
	"strings"
	"unicode"
)

const (
	deadLinkMessage     = "relative link target does not exist"
	outsideLinkMessage  = "relative link target leaves the module root"
	absoluteLinkMessage = "link target starts with a slash; write it relative to the file"
)

// link is one link target in a Markdown file and the byte offset in the file
// where the target starts.
type link struct {
	target string
	off    int
}

// checkLinks records every relative link in a Markdown file under the module
// root whose target is not a file or directory in the tree. It covers the
// Markdown files the ASCII check covers.
func (g *gate) checkLinks() error {
	return g.walkTree(func(name string, d fs.DirEntry) error {
		if path.Ext(d.Name()) != ".md" {
			return nil
		}
		return g.scanLinks(name)
	})
}

// scanLinks records a finding at the start of every link target in name that
// fails linkFinding.
func (g *gate) scanLinks(name string) error {
	content, err := fs.ReadFile(g.root.FS(), name)
	if err != nil {
		return err
	}
	var file *token.File
	for _, l := range markdownLinks(content) {
		msg := g.linkFinding(name, l.target)
		if msg == "" {
			continue
		}
		if file == nil {
			file = g.file(name, content)
		}
		g.report(file, l.off, msg)
	}
	return nil
}

// linkFinding returns the finding for target, read from the file name, or ""
// when target is not a relative reference or names a file or directory in the
// tree. A fragment is not checked, and the target is not percent-decoded.
func (g *gate) linkFinding(name, target string) string {
	if target == "" || strings.HasPrefix(target, "#") || hasScheme(target) {
		return ""
	}
	if strings.HasPrefix(target, "/") {
		return absoluteLinkMessage
	}
	rel, _, _ := strings.Cut(target, "#")
	resolved := path.Join(path.Dir(name), rel)
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return outsideLinkMessage
	}
	if _, err := fs.Stat(g.root.FS(), resolved); err != nil {
		return deadLinkMessage
	}
	return ""
}

// hasScheme reports whether target starts with a URI scheme -- a letter, then
// letters, digits, '+', '-' or '.', then ':' -- so it is not a relative
// reference.
func hasScheme(target string) bool {
	i := strings.IndexByte(target, ':')
	if i < 1 {
		return false
	}
	for k, r := range target[:i] {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case k > 0 && (r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.'):
		default:
			return false
		}
	}
	return true
}

// markdownLinks returns the target of every inline link or image and every
// reference definition in content that sits outside a fenced code block and
// outside a code span. It reads lines, not a Markdown tree: a fence is a line
// that starts, after leading white space, with three backticks or three
// tildes, and it toggles the fenced state.
func markdownLinks(content []byte) []link {
	var links []link
	fenced := false
	off := 0
	for _, line := range strings.SplitAfter(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "```"), strings.HasPrefix(trimmed, "~~~"):
			fenced = !fenced
		case !fenced:
			links = append(links, lineLinks(blankCodeSpans(line), off)...)
		}
		off += len(line)
	}
	return links
}

// lineLinks returns the link targets in one line whose code spans are blanked.
// off is the offset of the line in its file.
func lineLinks(line string, off int) []link {
	var links []link
	if target, start, ok := refDefinition(line); ok {
		links = append(links, link{target: target, off: off + start})
	}
	rest, base := line, off
	for {
		i := strings.Index(rest, "](")
		if i < 0 {
			return links
		}
		start := i + len("](")
		links = append(links, link{target: inlineTarget(rest[start:]), off: base + start})
		rest, base = rest[start:], base+start
	}
}

// inlineTarget returns the destination at the start of s, the text after
// "](": up to the closing angle bracket when it opens with one, otherwise up
// to the first closing parenthesis or white space. An angle bracket that
// never closes yields no target.
func inlineTarget(s string) string {
	if inner, ok := strings.CutPrefix(s, "<"); ok {
		target, _, found := strings.Cut(inner, ">")
		if !found {
			return ""
		}
		return target
	}
	if i := strings.IndexFunc(s, func(r rune) bool { return r == ')' || unicode.IsSpace(r) }); i >= 0 {
		return s[:i]
	}
	return s
}

// refDefinition returns the target of a reference definition -- a line that
// reads "[label]: target" after leading white space, with a non-empty label
// and white space after the colon -- and the target's offset in the line.
func refDefinition(line string) (string, int, bool) {
	rest, ok := strings.CutPrefix(strings.TrimLeft(line, " \t"), "[")
	if !ok {
		return "", 0, false
	}
	label, rest, ok := strings.Cut(rest, "]")
	if !ok || label == "" {
		return "", 0, false
	}
	rest, ok = strings.CutPrefix(rest, ":")
	if !ok {
		return "", 0, false
	}
	value := strings.TrimLeft(rest, " \t")
	if len(value) == len(rest) {
		return "", 0, false
	}
	target := value
	if i := strings.IndexFunc(value, unicode.IsSpace); i >= 0 {
		target = value[:i]
	}
	if target == "" {
		return "", 0, false
	}
	return target, len(line) - len(value), true
}

// blankCodeSpans returns line with every code span replaced by spaces of the
// same length, so a link written inside one is not read and every offset
// stays where it was. A span opens with a run of backticks and closes at the
// next run of the same length on the line; a run that never closes is text.
func blankCodeSpans(line string) string {
	b := []byte(line)
	for i := 0; i < len(b); {
		if b[i] != '`' {
			i++
			continue
		}
		run := backtickRun(b[i:])
		end := closingRun(b[i+run:], run)
		if end < 0 {
			i += run
			continue
		}
		stop := i + run + end + run
		for k := i; k < stop; k++ {
			b[k] = ' '
		}
		i = stop
	}
	return string(b)
}

// backtickRun returns the number of backticks b starts with.
func backtickRun(b []byte) int {
	n := 0
	for n < len(b) && b[n] == '`' {
		n++
	}
	return n
}

// closingRun returns the offset in b of the first run of exactly n backticks,
// or -1 when there is none.
func closingRun(b []byte, n int) int {
	for k := 0; k < len(b); {
		if b[k] != '`' {
			k++
			continue
		}
		m := backtickRun(b[k:])
		if m == n {
			return k
		}
		k += m
	}
	return -1
}
