# Local sigstore harness

A rootless-Podman-compatible local sigstore stack: Keycloak (IdP) behind a Caddy
TLS terminator, Fulcio (CA), and Rekor v2 (POSIX tile log). It exercises the
keyless chain for the strike keyless harness and is independent test
infrastructure -- not part of the strike binary.

## Prerequisites

- Rootless Podman with the compose provider (`podman compose`), or Docker
  Compose (`make up COMPOSE="docker compose"`).
- Internet access for DNS by default: the canonical hostname resolves via
  sslip.io. No `/etc/hosts` entry and no root are needed. Offline or
  restricted hosts can use alternative resolution -- see "Resolving the
  canonical issuer" below.

## Bring-up

    make up
    make check-issuer   # both lines must print the same issuer string
    make token          # print an OIDC id_token for tester@strike.localhost
    make tsa-certchain  # fetch the TSA certificate chain to pki/tsa-certchain.pem

## Endpoints

Every service is TLS-terminated by Caddy under one internal root
(`pki/caddy-root.crt`) and reached over HTTPS via sslip.io. There is no
plaintext endpoint -- a strike keyless producer pins this root as its
`#TLSTrust` `ca_bundle` for every endpoint:

- Fulcio: `https://fulcio.127.0.0.1.sslip.io:5555`
- Rekor v2: `https://rekor.127.0.0.1.sslip.io:3003`
- TSA: `https://tsa.127.0.0.1.sslip.io:3004`
- Issuer (Keycloak): `https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore`

## Layout

- `compose.yaml` -- the stack. witness and probe are non-default profiles; TSA
  runs by default (Rekor v2 Path 1 requires RFC3161 timestamps).
- `caddy/Caddyfile` -- TLS terminator (internal CA) + reverse proxy to
  Keycloak, Fulcio, Rekor, and TSA. Every service strike dials is reached over
  HTTPS under the Caddy internal root; there is no plaintext endpoint.
- `fulcio/config.yaml` -- OIDC issuer (canonical issuer, type email).
- `keycloak/realm-export.json` -- realm `sigstore`, public client `sigstore`,
  direct access grant on, verified test user `tester` / `tester`,
  email `tester@strike.localhost`.
- `pki/` -- generated ed25519 rekor signer key and its exported public key
  (`rekor-ed25519-pub.pem`), the persistent Fulcio fileca root
  (`fulcio-root.crt` + encrypted `fulcio-root.key`), the CT log (ctfe) signer
  key (`ctfe.key`) and its exported public key (`ctfe-pub.pem`, for trust-root
  assembly), and the exported Caddy root (`caddy-root.crt`). Never committed.

## Canonical issuer and trust anchor

Issuer: `https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore`, byte-identical
from the host browser and from inside the Fulcio container:

- host-side, sslip.io resolves the name to 127.0.0.1 -> the published 8443 port
  -> Caddy;
- in-network, a Caddy network alias for the exact same FQDN overrides sslip.io
  -> the Caddy container.

Caddy terminates TLS with its internal CA. The pinnable trust anchor is Caddy's
root (`pki/caddy-root.crt`, exported by `make caddy-root`); its 10-year root is
stable while the 12-hour leaf rotates under it, so a lane.yaml CA-bundle pin on
the root does not need re-pinning. This is stumbling block #1 (issuer-URL
consistency); `make check-issuer` is its gate.

## Resolving the canonical issuer

The issuer hostname, the issuer URL, the Caddy root you pin, and the `lane.yaml`
`oidc:` block are identical no matter how the name resolves. Switching the
resolution mechanism changes nothing on the strike side and nothing in the
trust chain -- it only changes how `keycloak.127.0.0.1.sslip.io` reaches
`127.0.0.1`.

Reachability is not trust. A missing, wrong, or hijacked DNS answer cannot
man-in-the-middle the issuer: strike pins the Caddy CA root (`pki/caddy-root.crt`)
and rejects any endpoint whose certificate is not issued under it. DNS only
decides whether you reach the right endpoint at all, never whether you trust it.

Only the host-side leg depends on host DNS: the strike controller's OIDC dial
and the host line of `make check-issuer`. The in-network leg (Fulcio reaching
Keycloak) always resolves through the Caddy network alias, online or offline, so
a failing host line means a host-resolution problem, not an unhealthy stack.

### Default: nothing to do

`keycloak.127.0.0.1.sslip.io` resolves to `127.0.0.1` through sslip.io's public
DNS. No `/etc/hosts` entry, no root, no resolver setup. This is the expected
path on an ordinary online host.

### If the host line of `make check-issuer` fails

The stack is healthy; your resolver simply is not returning `127.0.0.1` for the
issuer host. Confirm what it returns:

    getent hosts keycloak.127.0.0.1.sslip.io   # expect: 127.0.0.1 ...

You almost never have to stand anything up -- the resolver already exists, it
just has to answer this one name. Find the cause, then fix or escalate:

- **Corporate / air-gapped / split-horizon network.** Your host already uses an
  internal resolver that IT preconfigured; you do not deploy one. If it does not
  resolve `sslip.io`, ask IT to resolve it (forward the zone, or return
  `127.0.0.1` for the issuer host). This is the normal case in locked-down
  environments.

- **Ordinary network, but the answer is dropped or NXDOMAIN.** This is DNS
  rebinding (loopback) protection: the resolver refuses a public name that maps
  to `127.0.0.1`.
  - You control the resolver or router: exempt `sslip.io` from rebind
    protection (dnsmasq: `rebind-domain-ok=/sslip.io/`; other resolvers have an
    equivalent allow-list).
  - IT controls it: ask them to exempt `sslip.io` from rebind protection.

- **Everything else fails: `/etc/hosts`.** Independent of DNS entirely, the
  last resort.
  - You own the machine: add one line (one-time sudo):

        127.0.0.1 keycloak.127.0.0.1.sslip.io

  - IT owns the machine: ask IT to add that line, or to push it via config
    management.

In every branch the issuer URL and the pinned Caddy root are unchanged; you are
only making the name resolve.

## Tile read path

The sign/verify round trip needs no HTTP tile server: rekor returns the
inclusion proof at upload and it is persisted in the bundle, so verification is
offline against the trust root plus that proof. The tile read API is for log
monitors only, which this harness does not run. If a monitor is ever needed,
serve the rekor storage dir with a Caddy file_server profile -- do not add a
separate nginx for it.

## Certificate transparency (CT) log

Fulcio runs against a persistent `fileca` root and submits each issuance to a
TesseraCT log (`tesseract`, Tessera POSIX backend, no Trillian) fronted by Caddy
TLS at `https://ct.127.0.0.1.sslip.io:6962/strike-ct`, validated against the
Caddy root like every other endpoint -- there is no plaintext hop. The log
embeds an SCT in the issued leaf, so the leaf is self-describing: an independent
verifier checks the SCT offline against the CT log public key (`make
ctlog-pubkey` exports `pki/ctfe-pub.pem`) in the trusted root, and never dials
the log. Fulcio reaches the log in-network through the Caddy alias; the port is
published so `make up` can poll its health.

`fileca` (not `ephemeralca`) is required: the CT log pins its accepted roots
(`--roots_pem_file`), so the issuing CA must be fixed before the log starts. A
side effect is that the Fulcio root stops rotating per boot; only the TSA cert
and the per-signing leaf still rotate.

## First-run risks (verify here, iterate if needed)

- R-1 -- in-network alias. The alias must override sslip.io for the exact dotted
  FQDN. If the in-network `check-issuer` line resolves to the container's own
  loopback instead of Caddy, the alias is not matching; fix the alias to equal
  the issuer hostname exactly.
- R-2 -- witness. If `rekor` will not serve without a witness, bring it up with
  `make up COMPOSE="podman compose --profile witness"` (builds from source).
- R-3 -- Keycloak behind-proxy env. `KC_HOSTNAME` / `KC_PROXY_HEADERS` are
  version-sensitive; verify the discovery document's `issuer` field carries the
  https sslip.io host and port.
- R-4 -- image digests. Replace each `# PIN @sha256 at first run` tag.
- R-5 -- `compose cp`. If your compose provider does not support
  `compose cp SERVICE:PATH`, export the Caddy root with `podman cp <container>
  /data/caddy/pki/authorities/local/root.crt pki/caddy-root.crt` instead.
- R-6 -- Fulcio CA trust (WIRED). `pki/caddy-root.crt` is mounted into Fulcio
  and `SSL_CERT_FILE` points at it, so Fulcio validates Keycloak discovery TLS.
  `make up` brings Caddy up first, extracts the root, then starts the rest.
- caddy_data must be writable by the container user; with a named volume under
  rootless Podman this is automatic.

## The four classic failure points

1. Issuer-URL consistency -- see "Canonical issuer and trust anchor".
2. `aud` == client-id -- token audience must equal `sigstore`.
3. `email` + `email_verified: true` -- present via the `email` scope and the
   verified test user.
4. Client versions -- cosign >= v3.0.1 or >= v2.6.0 for Rekor v2 (used by
   `make conformance`; see "Conformance" below).

## Conformance (independent cosign verification)

`make conformance` verifies the committed golden bundles
(`internal/verify/testdata/golden/`) with cosign as an independent verifier,
fully offline -- no harness bring-up. It is the regression baseline for the
verification arcs: if strike's emitted bundles stop verifying under independent
tooling, this fails. cosign verifies the embedded SCT against the CT log key in
the trusted root, so no insecure flag is needed.

All three statement layers (sealed, engine-context, informational) are verified
and reported, but only the sealed (V) layer gates the exit; the engine-context
and informational layers never block, mirroring strike's own trust model.
Requires cosign (>= v3.0.1 or >= v2.6.0 for Rekor v2).

## Downstream coupling (not implemented here)

Once the harness stands, the runnable smoke lane's `lane.yaml` `oidc:` block
takes the harness values: issuer
`https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore`, client_id `sigstore`,
identity `tester@strike.localhost`, and trust = the CA bundle
`pki/caddy-root.crt`. The placeholder fixtures (example.com) are untouched; only
lane.yaml couples. Instruction 5 (verify) must keep the trust root
parametrizable: the ephemeral harness root for local, the public Sigstore TUF
root in production. The Fulcio ephemeralca signing root rotates per restart and
is re-exported each `up`; the Caddy IdP-TLS root does not.
