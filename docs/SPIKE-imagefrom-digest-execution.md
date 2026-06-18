# SPIKE -- imageFrom digest-execution transport (alpha vs beta)

Anchor: `429b79dffd838bd12af05dfe41e38852e277455e`

## P0 -- wrapped image digest and inspect

Image wrapped via `WrapImageOutputAsImage` (OCI layout tar of a single-file
scratch layer). The tag used was `localhost/strike/spike/p1:probe0`.

- Digest D: `sha256:5bdb3f74f82c176485e34d5260cace5888bb6d4c2c20ed886a3be32d2e47265b`
- Inspect Digest: `sha256:5bdb3f74f82c176485e34d5260cace5888bb6d4c2c20ed886a3be32d2e47265b`
- Inspect RepoDigests: `[localhost/strike/spike/p1@sha256:5bdb3f74f82c176485e34d5260cace5888bb6d4c2c20ed886a3be32d2e47265b]`

Key observation: libpod records a RepoDigest entry at tag time in the form
`<repo>@<digest>` (repo is the tag's repository, no tag suffix). Loaded images
are NOT digest-orphaned under libpod when tagged with a `localhost/` reference.

Controller == engine digest: confirmed (wrap invariant holds at runtime).

## P1 -- run locally-loaded image by manifest digest

Digest reference tested: `localhost/strike/spike/p1@sha256:5bdb3f74...265b`

- `ImageExists(digestRef)` = `true` -- reference resolves in local store.
- `ContainerRun(image=digestRef, cmd=["true"])` exit code -1, error:

```
container start: start: status 500: {"cause":"OCI runtime attempted to invoke
a command that was not found","message":"runc: runc create failed: unable to
start container process: exec: \"true\": executable file not found in
$PATH: OCI runtime attempted to invoke a command that was not found",
"response":500}
```

The failure is an OCI runtime exec error (no binary in the probe scratch
image), not an image-resolution error. The container was created and started
from the digest reference; libpod found the image via its RepoDigest entry.
The image-ID reference (`2c2d7dff4313...`) produces the identical exec error,
confirming both reference forms reach the same image.

P2 was not reached; P1 is decisive.

## Recommendation: alpha

Rationale: libpod resolves a locally-loaded, strike-tagged image by
`<repo>@sha256:<D>` without a registry pull. The required RepoDigest entry
(`localhost/strike/<lane>/<step>@sha256:<D>`) is recorded automatically by
libpod at `ImageTag` time, so the digest-to-repo binding is already present
when `WrapImageArchiveAsImage` returns. No registry roundtrip is needed.

Caveat for byte-exact 7a authoring: the reference form that resolves is the
repository component of the WrapTag (strip the `:spec_hash` suffix) plus
`@sha256:<D.Hex>`. Example: WrapTag `localhost/strike/lane1/build:abc123`
-> execution reference `localhost/strike/lane1/build@sha256:<D>`.
