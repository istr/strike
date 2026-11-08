package main

import (
	"encoding/json"
	"fmt"
	"go/token"
	"io/fs"
	"path"
	"slices"
	"strings"
)

// containerfileNames are the base names of the files the container check reads
// as Containerfiles.
var containerfileNames = map[string]bool{"Containerfile": true, "Dockerfile": true}

// composeNames are the base names of the compose files whose service images
// the container check reads.
var composeNames = map[string]bool{
	"compose.yaml":        true,
	"compose.yml":         true,
	"docker-compose.yaml": true,
	"docker-compose.yml":  true,
}

// devcontainerNames are the base names of the dev container configurations the
// container check reads.
var devcontainerNames = map[string]bool{"devcontainer.json": true, ".devcontainer.json": true}

const (
	notPinnedMessage        = "external image reference without a sha256 digest"
	checksumMessage         = "remote ADD source without --checksum"
	shellFormMessage        = "shell-form RUN; write the exec form"
	execFormMessage         = "exec-form RUN is not a JSON array of strings"
	programMessage          = "RUN starts a program the Containerfile policy does not allow"
	continuationMessage     = "line continuation; write one instruction per line"
	featuresMessage         = "dev container declares features; the image arrives through its Containerfile"
	devcontainerJSONMessage = "dev container configuration is not plain JSON"
	staleExceptionMessage   = "Containerfile exception matches no offending instruction"
)

// containerfilePolicy is what one Containerfile may use besides images pinned
// by digest: the programs an exec-form RUN may start and the named build
// contexts an instruction may read from. Everything in an image arrives
// through a pinned reference (docs/ADR-055-hardened-endpoint-development-premise.md,
// D3), so no program that resolves a name against a package index belongs in
// a policy.
type containerfilePolicy struct {
	programs []string
	contexts []string
}

// containerfilePolicies holds the policy of each Containerfile, keyed by its
// path relative to its module root. A Containerfile that is not listed may
// start no program and read no named context.
var containerfilePolicies = map[string]containerfilePolicy{
	".devcontainer/Containerfile": {programs: []string{"/usr/bin/busybox", "go"}},
	"bootstrap/Containerfile":     {programs: []string{"git", "go"}, contexts: []string{"harness"}},
}

// containerfileException is one Containerfile instruction the check tolerates
// although it breaks a rule: the file and the instruction as written, the
// roadmap item that removes it, and why it stands until then. An exception
// that matches no offending instruction is itself a finding, so the change
// that fixes the instruction also removes the entry.
type containerfileException struct {
	file        string
	instruction string
	owner       string
	reason      string
}

// containerfileExceptions are the instructions the check tolerates.
var containerfileExceptions = []containerfileException{
	{
		file:        "bootstrap/Containerfile",
		instruction: `RUN ["apk", "add", "--no-cache", "git"]`,
		owner:       "item-0151",
		reason:      "the builder stage installs git from the distribution index until its base image carries what the build needs",
	},
	{
		file:        "bootstrap/Containerfile",
		instruction: "RUN git fetch --depth 1 https://github.com/istr/strike ${GIT_COMMIT}",
		owner:       "item-0151",
		reason:      "the residual GIT_COMMIT shell expansion, a stage_0 debt (docs/ADR-009-bootstrap-reproducibility-proof.md)",
	},
}

// instruction is one Containerfile instruction: its text without surrounding
// space and the offset of the line it starts on.
type instruction struct {
	text string
	off  int
}

// containerfileScan is the state a Containerfile carries from instruction to
// instruction: the stage names declared so far and the file's policy.
type containerfileScan struct {
	stages map[string]bool
	policy containerfilePolicy
}

// checkContainers reads every Containerfile, compose file and dev container
// configuration in the tree, then reports each exception no offending
// instruction used.
func (g *gate) checkContainers() error {
	used := make([]bool, len(containerfileExceptions))
	err := g.walkTree(func(name string, d fs.DirEntry) error {
		switch base := d.Name(); {
		case containerfileNames[base]:
			return g.scanContainerfile(name, used)
		case composeNames[base]:
			return g.scanCompose(name)
		case devcontainerNames[base]:
			return g.scanDevcontainer(name)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i, e := range containerfileExceptions {
		if !used[i] {
			g.found = append(g.found, fmt.Sprintf("%s: %s: %s (owner %s)", e.file, staleExceptionMessage, e.instruction, e.owner))
		}
	}
	return nil
}

// scanContainerfile checks one Containerfile instruction by instruction and
// marks the exceptions its offending instructions match.
func (g *gate) scanContainerfile(name string, used []bool) error {
	content, err := fs.ReadFile(g.root.FS(), name)
	if err != nil {
		return err
	}
	key := moduleRelative(g.root.FS(), name)
	scan := containerfileScan{stages: map[string]bool{}, policy: containerfilePolicies[key]}
	var file *token.File
	for _, ins := range containerfileInstructions(content) {
		msgs := scan.check(ins.text)
		if len(msgs) == 0 {
			continue
		}
		if i := exceptionIndex(key, ins.text); i >= 0 {
			used[i] = true
			continue
		}
		if file == nil {
			file = g.file(name, content)
		}
		for _, msg := range msgs {
			g.report(file, ins.off, msg)
		}
	}
	return nil
}

// containerfileInstructions splits content into instructions, one per line,
// skipping blank and comment lines. A line that ends in a backslash is kept
// as written; check reports it, so no instruction hides behind a line break.
func containerfileInstructions(content []byte) []instruction {
	var out []instruction
	off := 0
	for _, line := range strings.SplitAfter(string(content), "\n") {
		if text := strings.TrimSpace(line); text != "" && !strings.HasPrefix(text, "#") {
			out = append(out, instruction{text: text, off: off})
		}
		off += len(line)
	}
	return out
}

// check returns the findings of one instruction. Keywords without an image
// reference or a command pass.
func (c *containerfileScan) check(text string) []string {
	if strings.HasSuffix(text, `\`) {
		return []string{continuationMessage}
	}
	keyword, rest, _ := strings.Cut(text, " ")
	rest = strings.TrimSpace(rest)
	switch strings.ToUpper(keyword) {
	case "FROM":
		return c.checkFrom(rest)
	case "COPY":
		return c.checkFlags(rest, false)
	case "ADD":
		return c.checkFlags(rest, true)
	case "RUN":
		return c.checkRun(rest)
	}
	return nil
}

// checkFrom checks the image of a FROM and records the stage name it declares.
// Flags such as --platform come before the image; the stage name follows AS.
func (c *containerfileScan) checkFrom(rest string) []string {
	fields := strings.Fields(rest)
	for len(fields) > 0 && strings.HasPrefix(fields[0], "--") {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return []string{notPinnedMessage}
	}
	msgs := c.checkImage(fields[0])
	if len(fields) == 3 && strings.EqualFold(fields[1], "AS") {
		c.stages[strings.ToLower(fields[2])] = true
	}
	return msgs
}

// checkFlags checks a COPY or an ADD: an image --from names is checked like a
// FROM, and a remote ADD source needs --checksum, because nothing else pins
// what the URL returns. COPY fetches nothing, so only ADD is held to the
// checksum.
func (c *containerfileScan) checkFlags(rest string, add bool) []string {
	var msgs []string
	checksum, remote := false, false
	for _, field := range strings.Fields(rest) {
		if from, ok := strings.CutPrefix(field, "--from="); ok {
			msgs = append(msgs, c.checkImage(from)...)
		}
		checksum = checksum || strings.HasPrefix(field, "--checksum=")
		src := strings.Trim(field, `[]",`)
		remote = remote || strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "git@")
	}
	if add && remote && !checksum {
		msgs = append(msgs, checksumMessage)
	}
	return msgs
}

// checkRun checks a RUN: an image a --mount reads from is checked like a FROM,
// and the command is the exec form, a JSON array whose first element the
// file's policy names. A shell-form command is a finding, because the check
// cannot see what a shell will start.
func (c *containerfileScan) checkRun(rest string) []string {
	var msgs []string
	for strings.HasPrefix(rest, "--") {
		flag, after, _ := strings.Cut(rest, " ")
		if opts, ok := strings.CutPrefix(flag, "--mount="); ok {
			for _, opt := range strings.Split(opts, ",") {
				if from, isFrom := strings.CutPrefix(opt, "from="); isFrom {
					msgs = append(msgs, c.checkImage(from)...)
				}
			}
		}
		rest = strings.TrimSpace(after)
	}
	if !strings.HasPrefix(rest, "[") {
		return append(msgs, shellFormMessage)
	}
	var argv []string
	if err := json.Unmarshal([]byte(rest), &argv); err != nil || len(argv) == 0 {
		return append(msgs, execFormMessage)
	}
	if !slices.Contains(c.policy.programs, argv[0]) {
		msgs = append(msgs, fmt.Sprintf("%s: %s", programMessage, argv[0]))
	}
	return msgs
}

// checkImage returns the finding for an image that is neither an earlier
// stage, nor a named build context of the file, nor pinned by digest.
func (c *containerfileScan) checkImage(ref string) []string {
	if c.stages[strings.ToLower(ref)] || slices.Contains(c.policy.contexts, ref) || hasDigest(ref) {
		return nil
	}
	return []string{notPinnedMessage}
}

// scanCompose checks the image of every service in a compose file. It reads
// lines, not YAML: an image is the value of a line whose first token is
// image:, unquoted before the check.
func (g *gate) scanCompose(name string) error {
	content, err := fs.ReadFile(g.root.FS(), name)
	if err != nil {
		return err
	}
	var file *token.File
	off := 0
	for _, line := range strings.SplitAfter(string(content), "\n") {
		ref, ok := strings.CutPrefix(strings.TrimSpace(line), "image:")
		if ok && !hasDigest(strings.Trim(strings.TrimSpace(ref), `"'`)) {
			if file == nil {
				file = g.file(name, content)
			}
			g.report(file, off, notPinnedMessage)
		}
		off += len(line)
	}
	return nil
}

// scanDevcontainer checks a dev container configuration: it declares no
// feature, and an image it names instead of a Containerfile is pinned by
// digest. The file must be plain JSON, which the format's tolerated comments
// are not.
func (g *gate) scanDevcontainer(name string) error {
	content, err := fs.ReadFile(g.root.FS(), name)
	if err != nil {
		return err
	}
	var cfg struct {
		Image    *string         `json:"image"`
		Features json.RawMessage `json:"features"`
	}
	var msgs []string
	if jsonErr := json.Unmarshal(content, &cfg); jsonErr != nil {
		msgs = append(msgs, devcontainerJSONMessage)
	}
	if cfg.Features != nil {
		msgs = append(msgs, featuresMessage)
	}
	if cfg.Image != nil && !hasDigest(*cfg.Image) {
		msgs = append(msgs, notPinnedMessage)
	}
	if len(msgs) == 0 {
		return nil
	}
	file := g.file(name, content)
	for _, msg := range msgs {
		g.report(file, 0, msg)
	}
	return nil
}

// hasDigest reports whether an image reference ends in a sha256 digest: the
// separator followed by exactly 64 lowercase hex digits.
func hasDigest(ref string) bool {
	_, digest, ok := strings.Cut(ref, "@sha256:")
	return ok && len(digest) == 64 && strings.Trim(digest, "0123456789abcdef") == ""
}

// moduleRelative returns name relative to the closest directory above it that
// holds a go.mod, so a checkout nested in the tree -- a git worktree, say --
// is keyed like the tree itself. name is relative to the module root, which
// is not consulted.
func moduleRelative(fsys fs.FS, name string) string {
	for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
		if _, err := fs.Stat(fsys, path.Join(dir, "go.mod")); err == nil {
			return strings.TrimPrefix(name, dir+"/")
		}
	}
	return name
}

// exceptionIndex returns the index of the exception for one instruction of the
// Containerfile at key, or -1.
func exceptionIndex(key, text string) int {
	return slices.IndexFunc(containerfileExceptions, func(e containerfileException) bool {
		return e.file == key && e.instruction == text
	})
}
