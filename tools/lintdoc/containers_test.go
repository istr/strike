package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// testDigest is a well-formed digest suffix that names no real image.
const testDigest = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestHasDigest(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		{ref: "img" + testDigest, want: true},
		{ref: "registry.example.com/img:1.0" + testDigest, want: true},
		{ref: "img:1.0", want: false},
		{ref: "img@sha256:0123", want: false},
		{ref: "img" + strings.ToUpper(testDigest), want: false},
		{ref: "img" + testDigest + "0", want: false},
		{ref: "img@sha512:" + strings.Repeat("0", 64), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			if got := hasDigest(tt.ref); got != tt.want {
				t.Fatalf("hasDigest(%q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}

func TestContainerfileInstructions(t *testing.T) {
	content := "# comment\n\nFROM a\n  RUN [\"go\"]  \n"
	got := containerfileInstructions([]byte(content))
	want := []instruction{{text: "FROM a", off: 11}, {text: `RUN ["go"]`, off: 18}}
	if !slices.Equal(got, want) {
		t.Fatalf("instructions = %v, want %v", got, want)
	}
}

func TestContainerfileCheck(t *testing.T) {
	program := fmt.Sprintf("%s: %s", programMessage, "apk")
	tests := []struct {
		name string
		text []string
		want []string
	}{
		{name: "pinned from", text: []string{"FROM img" + testDigest}},
		{name: "tagged from", text: []string{"FROM img:1.0"}, want: []string{notPinnedMessage}},
		{name: "tagged from with stage name", text: []string{"FROM img:1.0 AS x"}, want: []string{notPinnedMessage}},
		{name: "lowercase keyword", text: []string{"from img:1.0"}, want: []string{notPinnedMessage}},
		{name: "from with platform flag", text: []string{"FROM --platform=linux/amd64 img" + testDigest + " AS build"}},
		{name: "from without image", text: []string{"FROM --platform=linux/amd64"}, want: []string{notPinnedMessage}},
		{name: "earlier stage", text: []string{"FROM img" + testDigest + " AS Build", "FROM build AS next", "COPY --from=next /a /b"}},
		{name: "copy from image", text: []string{"COPY --from=img:1.0 /a /b"}, want: []string{notPinnedMessage}},
		{name: "copy from named context", text: []string{"COPY --from=ctx a /b"}},
		{name: "copy of a url fetches nothing", text: []string{"COPY https://example.com/a /a"}},
		{name: "add remote without checksum", text: []string{"ADD https://example.com/a.tgz /a"}, want: []string{checksumMessage}},
		{name: "add plain http without checksum", text: []string{"ADD http://example.com/a.tgz /a"}, want: []string{checksumMessage}},
		{name: "add git source without checksum", text: []string{"ADD git@example.com:a/b.git /a"}, want: []string{checksumMessage}},
		{name: "add exec form without checksum", text: []string{`ADD ["https://example.com/a", "/a"]`}, want: []string{checksumMessage}},
		{name: "add remote with checksum", text: []string{"ADD --checksum=sha256:00 https://example.com/a.tgz /a"}},
		{name: "add local", text: []string{"ADD a /a"}},
		{name: "run allowed program", text: []string{`RUN ["go", "build"]`}},
		{name: "run program not allowed", text: []string{`RUN ["apk", "add", "git"]`}, want: []string{program}},
		{name: "run shell form", text: []string{"RUN go build"}, want: []string{shellFormMessage}},
		{name: "run flag only", text: []string{"RUN --network=none"}, want: []string{shellFormMessage}},
		{name: "run malformed exec form", text: []string{`RUN ["go", `}, want: []string{execFormMessage}},
		{name: "run empty exec form", text: []string{"RUN []"}, want: []string{execFormMessage}},
		{name: "run mount from stage", text: []string{"FROM img" + testDigest + " AS tools", `RUN --mount=type=bind,from=tools,target=/t ["go", "version"]`}},
		{name: "run mount from image", text: []string{`RUN --mount=type=bind,from=img:1.0,target=/t ["go", "version"]`}, want: []string{notPinnedMessage}},
		{name: "line continuation", text: []string{`RUN go build \`}, want: []string{continuationMessage}},
		{name: "other keywords", text: []string{"WORKDIR /src", "ENV A=b", "USER dev"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scan := containerfileScan{
				stages: map[string]bool{},
				policy: containerfilePolicy{programs: []string{"go"}, contexts: []string{"ctx"}},
			}
			var got []string
			for _, text := range tt.text {
				got = append(got, scan.check(text)...)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("findings = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCheckContainers(t *testing.T) {
	g, dir := tempGate(t)
	pinned := "FROM img" + testDigest + "\n"
	writeFile(t, dir, "bootstrap/Containerfile", pinned+`RUN ["git", "init"]`+"\n"+"COPY --from=harness a /b\n")
	writeFile(t, dir, "wt/.git", "gitdir: ../.git/worktrees/wt\n")
	writeFile(t, dir, "wt/bootstrap/Containerfile", pinned+`RUN ["git", "init"]`+"\n")
	writeFile(t, dir, "clone/.git/HEAD", "ref: refs/heads/main\n")
	writeFile(t, dir, "clone/Containerfile", "FROM img:1.0\n")
	writeFile(t, dir, "mod/go.mod", "module mod\n")
	writeFile(t, dir, "mod/bootstrap/Containerfile", pinned+`RUN ["git", "init"]`+"\n")
	writeFile(t, dir, "other/Containerfile", pinned+`RUN ["go", "build"]`+"\n")
	writeFile(t, dir, "test/compose.yaml", "services:\n  a:\n    image: \"img"+testDigest+"\"\n  b:\n    image: img:1.0\n")
	writeFile(t, dir, ".devcontainer/devcontainer.json", `{"build": {"dockerfile": "Containerfile"}}`)
	writeFile(t, dir, "feat/.devcontainer.json", `{"features": {}}`)
	writeFile(t, dir, "img/devcontainer.json", `{"image": "img:1.0"}`)
	writeFile(t, dir, "jsonc/devcontainer.json", "// comment\n{}")
	if err := g.checkContainers(); err != nil {
		t.Fatalf("checkContainers: %v", err)
	}
	want := []string{
		"feat/.devcontainer.json:1:1: " + featuresMessage,
		"img/devcontainer.json:1:1: " + notPinnedMessage,
		"jsonc/devcontainer.json:1:1: " + devcontainerJSONMessage,
		"mod/bootstrap/Containerfile:2:1: " + programMessage + ": git",
		"other/Containerfile:2:1: " + programMessage + ": go",
		"test/compose.yaml:5:1: " + notPinnedMessage,
	}
	got := slices.Sorted(slices.Values(g.found))
	if !slices.Equal(got, want) {
		t.Fatalf("findings = %q, want %q", got, want)
	}
}
