# ADR-038 Implementation Roadmap

## Status: PARTIAL

ADR-038 is accepted. Pre-front trust-material delivery is in progress;
the front itself is not yet implemented. The current codebase runs a mix
of superseded and partially migrated mechanisms:

- `internal/executor/sshagent.go` -- ADR-025 agent socket forwarding (active;
  removal is roadmap item 6)
- `internal/capsule/sshforward.go` -- ADR-033 raw TCP splice forwarding (active)
- `internal/executor/sshknownhosts.go` -- per-step SSH trust content production
  (`SSHTrustContent`, `SSHTrustTar`); bind-mount delivery removed for the run
  path, replaced by read-only named volumes masking `/etc/ssh`
- `cmd/strike/run.go` -- `planTrustVolumes` creates and seeds the lane-wide CA
  volume and per-step SSH volumes in one `SeedVolumes` batch after `lane.Build`
- Deploy path: SSH peers rejected with a not-implemented error until the
  ADR-038 front lands the additional protocols the deploy path requires

## What needs to be implemented

### 1. Control-plane front (D2)

A single, run-level component that terminates container-facing sessions
(SSH, TLS, DoT), reads the in-band capability token, and dispatches to
per-step capsule contexts. Holds run-level ephemeral crypto (one SSH host
key, one TLS CA per lane run).

### 2. STRIKE_PEER capability token + dispatch table (D5)

High-entropy random token encoding (step, peer), issued per step per peer,
injected via `SetEnv STRIKE_PEER=<token>` in system-wide ssh_config `Host`
blocks. Fail-closed on unknown/absent token. Replaces the per-peer host-port
mux entirely.

### 3. SSH server and client (`golang.org/x/crypto/ssh`)

The front terminates SSH framing (transport, userauth, channel requests) so
the exec/subsystem request is visible for allowlist checking. Upstream client
authenticates from the host ssh-agent reached by the front directly (never
forwarded into the container).

### 4. Command allowlist (D1)

Initial allowlist: `git-upload-pack`, `git-receive-pack`. Anything not on
the list (shell, arbitrary command, port forwarding, agent forwarding) is
refused. Later additions: `sftp`, `rsync --server`, `scp -t`/`scp -f`.

### 5. Per-step capsule context refactor (D2)

Capsule retains per-step policy (declared peer set, trust anchors, upstream
dial logic, allowlist) but loses its container-facing listener and crypto
endpoint (both lift to the front). The allocator loses per-step SSH port
blocks and the `containerPorts` parameter.

### 6. In-container agent socket removal

Remove the ADR-025 `SSH_AUTH_SOCK` injection and agent proxy. Container
presents `none` to the front. Eliminates the in-container signing oracle.

### 7. Synthetic container ssh_config + known_hosts

All declared peer hostnames map to the single front identity (ephemeral
host key). The real peer's known_hosts is validated by the front upstream,
not mounted into the container. `GIT_SSH_COMMAND` replaced by system-wide
ssh_config injection.

**Partial (run path):** Per-step SSH trust volumes deliver `ssh_known_hosts`
and `ssh_config` at `/etc/ssh` via read-only named volumes. The `-F`
override in `GIT_SSH_COMMAND` is removed; the SSH client reads
system-wide config. `ConfigureSSHPeers` bind-mount path is deleted for
the run path; replaced by `SSHTrustContent` + `SSHTrustTar` (content
only, no disk I/O). `planTrustVolumes` batches CA + SSH volumes in a
single `SeedVolumes` call. Deploy path deferred (SSH peers rejected).

### 8. DoT resolver and TLS mediator rehosting onto the front

The resolver and TLS mediator lift from per-step capsule listeners to the
single front endpoint. HTTPS demuxed by SNI; DoT resolves lane-permissively
(no per-step token for DNS).

### 9. Phase-2 per-peer connection records (D7)

Per mediated SSH connection, split into:
- Observed (Layer V): upstream host-key fingerprint, negotiated algorithms,
  allowlisted command.
- Engine-asserted (Layer E): attribution of connection to specific step.

Populates `engine_dependent` in the attestation predicate.

## Sequencing

Per `HANDOVER-ssh-egress-redesign.md`:

1. Predicate hardening (ADR-037) -- **DONE** (Instruction 44)
1b. Per-step SSH trust volumes; batch with CA before step loop --
    **DONE** (Instruction 60, run path only; deploy path deferred)
2. `STRIKE_PEER` token + front dispatch table; drop per-peer SSH port
   allocation
3. Front termination (run-level host key/CA) + capsule context refactor
4. SSH server/client with D1 command allowlist; agent in the front;
   synthetic container known_hosts
5. DoT resolver and TLS mediator rehosting onto the front
6. Phase-2 per-peer connection records with D7 observed/engine-asserted
   split

Dependency: externalize signing key (KMS/keyless) before the front's inbound
listener is exposed in a remote deployment (ADR-037 D5.1 ordering).

## References

- `HANDOVER-ssh-egress-redesign.md` -- frozen design handover
- `docs/ADR-038-protocol-mediated-ssh.md` -- governing ADR
- `docs/ADR-037-two-engine-trust-layers.md` -- trust-layer foundation
- `SPIKE-control-plane-front-step-demux.md` -- feasibility result
