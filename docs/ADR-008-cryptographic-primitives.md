# ADR-008: Cryptographic Primitives -- ECDSA P-256, scrypt + secretbox, crypto/rand

## Status

Accepted.

## Context

A signing-and-attestation tool must commit to a small set of
cryptographic primitives. Choosing too broadly invites algorithm
agility bugs and forces verifiers to implement every option strike
might emit. Choosing the wrong primitive produces a deprecation
problem later. The constraints are: industry-standard, FIPS-eligible
where possible, supported by Go's standard library without
third-party crypto code, and aligned with the wider Sigstore /
in-toto ecosystem strike participates in.

For asymmetric signing, the realistic options are RSA (large keys,
slower), ECDSA P-256 (Sigstore standard, NIST curve), Ed25519
(modern, fast, but not the Sigstore default at the time of this
decision), and various others. For password-based key encryption
(when private keys are stored at rest in cosign-format files), the
options are scrypt+secretbox (cosign convention), Argon2id+AES-GCM,
or PBKDF2-derived AES-GCM. For randomness, the options are `crypto/rand`,
hardware RNG via `/dev/hwrng`, or `math/rand` (insecure, never).

## Decision

- Asymmetric signing: **ECDSA P-256** via `crypto/ecdsa`. Matches
  Sigstore's default and lets strike interoperate with the existing
  Rekor/Fulcio ecosystem without translation layers.
- Hash: **SHA-256** as the canonical hash everywhere. No SHA-1, no
  SHA-3, no BLAKE family, no per-call algorithm choice.
- Encrypted private keys (cosign-format): **scrypt** for KDF,
  **NaCl `secretbox`** (XSalsa20 + Poly1305) for AEAD. Matches the
  cosign on-disk format directly so strike-produced keys interop
  with the cosign CLI.
- Randomness for any security-relevant operation: **`crypto/rand`**.
  `math/rand` is prohibited for security uses; depguard / forbidigo
  enforce this in CI.
- TLS minimum: **TLS 1.3**. `MinVersion: tls.VersionTLS13` on every
  TLS configuration. No TLS configuration overrides.
- HTTP-only is never acceptable for engine-API or registry traffic.
  `http://` is rejected at parse time; TLS is required for all TCP
  connections to the container engine.

## Consequences

- A verifier (Rust, future implementations) needs to support exactly
  one curve, one hash, one KDF, one AEAD, one TLS version. The cross-
  validation surface is small.
- Algorithm rotation, when it eventually happens, is a deliberate
  schema change, not a configuration option. This forces all
  implementations to track the rotation together.
- govulncheck runs in CI and reports only reachable vulnerable
  functions. Combined with the small primitive surface, the
  cryptographic dependency exposure is bounded.
- The `--require-signed` enforcement on OCI inputs uses the same
  ECDSA P-256 path: a signed attestation means signed-by-this-curve.

## Principles

- External references are digest-pinned (SHA-256 only)
- Code is liability (one primitive per role, no algorithm agility)
- Identity is asymmetric (signing primitive does not encode trust
  policy; trust is in the public key choice, not the algorithm)
