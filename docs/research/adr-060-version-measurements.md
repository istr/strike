# The Version of strike: Measurements Behind ADR-060 (status: 2026-11-17)

This document records the measurements behind
[ADR-060](../ADR-060-version-as-constant-of-the-source.md). They answer
how the Go project sets the version of its toolchain, what a check of a
commit's changes can and cannot tell a build, what the build paths of
strike see of the history, how a file can be embedded, and whether the
version pattern is the grammar it claims to be. The survey beside them
is [the state of play](adr-060-version-identification-state-of-play.md).

Every run was read-only on the trees it examined or ran in a scratch
directory that was removed afterwards. No run used the Go toolchain: the
measurements are git commands, searches of pinned source and one script
that compares two regular expressions. The tree of strike was read at
`62ec79777e0cd685fb1ee320be02abfa8a9a26cf`.

## Summary

- **A Go release is one commit that changes one file.** The commit
  tagged `go1.27.4` changes `VERSION` and nothing else. The main branch
  tracks no such file and states the release in development as a
  constant.
- **Between two releases the label stays.** 25 commits of the release
  branch between `go1.27.3` and `go1.27.4` carry `go1.27.3` in their
  tree.
- **A check of what a commit changed is a statement about history.** A
  commit and an empty commit on top of it share one tree and get
  different answers. After a fetch of depth 1 the check reports every
  file as changed.
- **Both build paths of strike fetch at depth 1,** and the lane's build
  step receives the tree without history.
- **An embedded file has to lie in its package directory and has to
  exist.** strike has no package at the module root.
- **The version pattern is Semantic Versioning 2.0.0 without build
  metadata.** Among 5,680,840 strings it accepts what the expression the
  Semantic Versioning site suggests accepts, less every string with
  build metadata.

## Method and scope

- **golang/go.** A partial clone from `https://github.com/golang/go`
  with trees and without blobs, fetched for the tags `go1.27rc1`,
  `go1.27.0`, `go1.27.3` and `go1.27.4`, the commits between the last
  two, and `master`. Files were read with `git show`, changes with
  `git diff-tree --name-status`.
- **The check on a commit.** A scratch repository with three commits:
  one that adds a file named `VERSION` and a source file, one that
  changes the source file, one empty. It was fetched at depth 1 and at
  depth 2 into two further scratch repositories.
- **strike.** Whole-file searches of the pinned tree.
- **The pattern.** A script that compiles two expressions and compares
  what they accept.

## The Go release procedure

Read at the tag `go1.27.4` and at `master` on 2026-11-17.

| Fact | Value |
| --- | --- |
| Commit of the tag `go1.27.4` | `7b2881024c95a11ddb86663a616340aa3a88b67f`, author Gopher Robot, 2026-11-10 |
| Files that commit changes | `VERSION`, modified; no other |
| Content of `VERSION` at the tag | two lines: `go1.27.4` and `time 2026-11-02T20:36:20Z` |
| Head of `release-branch.go1.27` | the same commit |
| Tags of the release line | `go1.27rc1` to `go1.27rc3`, `go1.27.0` to `go1.27.4` |
| Commit of `go1.27rc1` | `eefb454`, 2026-06-18; adds `VERSION`; its parent merges master into the release branch |
| Commit of `go1.27.0` | `8af2175`, 2026-08-19; modifies `VERSION` |
| Commits after `go1.27.3` up to `go1.27.4` | 26: the release commit and 25 others |
| First line of `VERSION` in the trees of those 25 | `go1.27.3` in every one |
| `master` at `98ead39515bda350d1d65de29718ac80e3b8aab3` | no `VERSION` at the root; `.gitignore` lists `/VERSION.cache` |
| `src/internal/goversion/goversion.go` at that commit | `const Version = 28`; at the tag `go1.27.4` it is 27 |

Three of the eight release commits were examined one by one: `go1.27rc1`,
`go1.27.0` and `go1.27.4`.

How the value reaches a binary, read in `src/cmd/dist` and
`src/cmd/link` at the tag:

- `findgoversion` returns the first line of `VERSION` when the file
  exists and is not empty. Otherwise it returns the content of
  `VERSION.cache`, and otherwise it builds a version from the constant
  of `goversion.go`, the marker `devel`, and the short hash and date of
  the last commit, read from git or jj. Without a file and without a
  repository the build stops and asks for a `VERSION` file.
- `mkbuildcfg` writes the result as `const version` into a generated
  file of `internal/buildcfg`.
- The linker stores `buildcfg.Version` as `runtime.buildVersion`.

So the file is read by a generator, and a build without the file depends
on version control.

## A check of what a commit changed

The check under test, on each commit:

```sh
git show --name-only --pretty="" HEAD | grep VERSION
```

| Case | Result |
| --- | --- |
| Full history, HEAD is the commit that adds `VERSION` | prints `VERSION` |
| Full history, HEAD is the later commit that does not touch it | prints nothing |
| That later commit after a fetch of depth 1 | prints `VERSION`; the commit shows both files of the tree as added |
| That later commit after a fetch of depth 2 | prints nothing |
| An empty commit on top of the commit that adds `VERSION` | prints nothing; both commits have the tree `45d730939b748cd400f6edea643c6169f9622434` |
| `git archive` of the commit that adds `VERSION` | no history to ask |

A query over the whole history has the same dependence:

- On the partial clone of golang/go, whose history was cut below
  `go1.27.3`, the query

  ```sh
  git log --follow --oneline --pretty=format:'%h %s' go1.27.4 -- VERSION
  ```

  lists two commits: the release commit and `62cbde4`, the commit at the
  cut, which does not change `VERSION`.
- With `--all`, `git log` also walks the HEAD of every linked worktree.
  In the analysis clone of strike the same query on `README.md` listed
  ten commits, three of which were scratch commits on no branch.

## What the build paths of strike see

| Path | How it obtains the source | History |
| --- | --- | --- |
| stage_0, `bootstrap/Containerfile` | `git fetch --depth 1` of the commit named by the build argument, then a checkout | one commit, no parent |
| The bootstrap lane, `bootstrap/lane.cue` | `git clone --revision=... --depth=1 --separate-git-dir=/out/git`; the step's one output is `tree` | the build step is given the tree; the git directory is no output |

Build lines at the anchor:

- `Makefile`, `AGENTS.md`, `CONTRIBUTING.md` and
  `bootstrap/Containerfile`: `-trimpath` and `-ldflags="-s -w"`.
- `bootstrap/lane.cue` and the build of the integration tests: the same
  and `-buildvcs=false`.

No line passes a version. A search of the lane schema for a conditional
(`when`, `if`, `condition`, `unless`) found none outside comments: a
step does not run or change its arguments by the result of another.

## Embedding a file

- The documentation of the `embed` package rules that a pattern is
  interpreted relative to the package directory and may not contain `.`
  or `..` as a path element (`src/embed/embed.go` at the tag
  `go1.27.4`).
- The Go command fails a build whose pattern matches no file
  (`src/cmd/go/internal/load/pkg.go`, read in a Go 1.24.7 tree).
- strike tracks no Go file at the module root.
- The tree already meets the first rule once: `internal/schema/schema.go`
  holds a copy of `cue.mod/module.cue` as a constant, with a test
  against drift, because the pattern cannot reach the module root.

## The version pattern

The pattern of `#SemVer`, with its two parts written out:

```text
number     = (0|[1-9][0-9]*)
identifier = (0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)
pattern    = ^number\.number\.number(-identifier(\.identifier)*)?$
```

It was compared with the expression the Semantic Versioning site
suggests for numbered groups, which the site lists as compatible with
ECMAScript, PCRE, Python and Go. Both were matched against the whole
string.

| Set | Size | Result |
| --- | --- | --- |
| Every string up to length 7 over `0 1 9 a Z - . _ +` | 5,380,840 | without `+`: both accept the same strings; with `+`: the pattern accepts none |
| Random strings of length 5 to 16 over `0 1 2 3 4 5 a - . Z` | 300,000 | both accept the same strings |
| Valid versions without build metadata | 29 | accepted by both |
| Valid versions with build metadata | 14 | accepted by the suggested expression, rejected by the pattern |
| Invalid strings | 48 | rejected by both |

`0.0.0-devel` is among the valid versions. The pattern uses character
classes, groups, alternation and repetition only.

## The tree at the anchor

- **No version.** No constant, no file and no command: the usage text
  names `run`, `validate`, `dag` and `verify`.
- **The builder.** `internal/deploy/project.go` writes `builder.id` from
  a constant; `contract/attest/predicate.cue` defines `#SLSABuilder`
  with `id` alone and names the map form of `version` as the reason for
  leaving it out.
- **The tool entry.** `internal/deploy/catalog.go` writes one tool
  component with the name `strike` and no version.
- **The golden fixtures.** `go tool gengolden` is the only caller that
  projects the synthetic attestation; no test recomputes a golden
  statement from the projection. Their README calls regeneration a
  deliberate act outside every gate.
- **The trust-layer map.** Its rows for the SLSA provenance are checked
  against the fields of `#StrikeExternalParameters`; `builder.id` has no
  row.
- **A typed constant of a generated scalar** exists twice:
  `internal/endpoint/dot.go` and `internal/testutil/dotresolver.go`.

## Scanners

Trivy's documentation of Go binaries names three places for the main
module's version, in this order: the build information, the linker
flags, and the symbol table; when none yields one, the version is empty.
It names `-trimpath` as a reason the linker flags are missing. A
constant is in none of the three.

## Not measured

- **The generator.** What `cue exp gengotypes` emits for a required
  `version` field and for `#SemVer` is predicted from the forms the tree
  already uses, not measured.
- **The stage_0 binary.** Whether it carries version-control data was
  not examined. The Go command documents stamping as its default, and
  the stage_0 build line does not disable it.
- **A scanner run.** No scanner was run against a binary of strike; that
  none finds a version there follows from the documentation and the
  build line.
- **The other five release commits** of the Go 1.27 line.

## Sources

- golang/go -- https://github.com/golang/go at the tag `go1.27.4` and
  at `master` of 2026-11-17.
- Go, package `embed` -- https://pkg.go.dev/embed
- Semantic Versioning 2.0.0 -- https://semver.org/
- Trivy documentation, Go --
  https://trivy.dev/docs/latest/guide/coverage/language/golang/
