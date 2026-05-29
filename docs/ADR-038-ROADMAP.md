# ADR-038 Implementation Roadmap

## Status: PARTIAL (items 1--4 done, items 5--6 remain)

ADR-038 is accepted. The control-plane front, STRIKE_PEER token dispatch,
SSH termination with command allowlist, and capsule bridge are implemented.
Connection lifecycle follows the "each side closes what it initiated"
principle: the front waits for the client/pasta close (no teardown timer);
the capsule force-closes its outbound SSH clients when the executor reaps
the container (`CloseOutbound`). The current codebase:

- `internal/front/front.go` -- run-level SSH front: terminates container-
  facing SSH, reads STRIKE_PEER token, dispatches to per-step capsule via
  `BridgePeer`. After a session, `sshConn.Wait()` lets the client or pasta
  drive the close (no timer).
- `internal/capsule/capsule.go` -- `BridgePeer` dials the real peer,
  tracks the `*ssh.Client` in the forwarder, and splices the channel.
  `CloseOutbound` force-closes tracked outbound clients on container reap.
- `internal/capsule/sshforward.go` -- per-peer raw TCP relay (ADR-033,
  retained for the legacy path) plus `trackClient`/`untrackClient`/
  `closeClients` for the SSH bridge path.
- `internal/executor/sshagent.go` -- ADR-025 agent socket forwarding (active;
  removal is roadmap item 6)
- `internal/executor/sshknownhosts.go` -- per-step SSH trust content production
  (`SSHTrustContent`, `SSHTrustTar`); delivered via read-only named volumes
  masking `/etc/ssh`
- `cmd/strike/run.go` -- `planTrustVolumes` creates and seeds the lane-wide CA
  volume and per-step SSH volumes in one `SeedVolumes` batch after `lane.Build`;
  `executeContainerStep` calls `caps.CloseOutbound()` after container reap
- Deploy path: SSH peers rejected with a not-implemented error until the
  ADR-038 front lands the additional protocols the deploy path requires

## What needs to be implemented

### 1. Control-plane front (D2) -- DONE

Single run-level component (`internal/front/front.go`) terminating
container-facing SSH, reading the in-band capability token, and
dispatching to per-step capsule contexts. Holds one ephemeral ed25519
SSH host key per lane run.

### 2. STRIKE_PEER capability token + dispatch table (D5) -- DONE

256-bit hex tokens issued per step per peer (`capsule.mintToken`),
injected via `SetEnv STRIKE_PEER=<token>` in system-wide ssh_config
Host blocks (`capsule.SSHConfig`). Front's `Register`/`Lookup`
dispatches to capsule; fail-closed on unknown/absent token.

### 3. SSH server and client (`golang.org/x/crypto/ssh`) -- DONE

Front terminates SSH framing (transport, `NoClientAuth`, channel
requests) so exec/subsystem is visible for allowlist checking. Upstream
client (`capsule.BridgePeer`) authenticates from the host ssh-agent
reached by the front's process directly (never forwarded into the
container). Connection lifecycle: front waits (`sshConn.Wait`) for
client/pasta close after the session; capsule force-closes its outbound
clients on container reap (`CloseOutbound`). No teardown timer.

### 4. Command allowlist (D1) -- DONE

`allowedSSHCommand`: `git-upload-pack`, `git-receive-pack`. Anything
else refused. Later additions: `sftp`, `rsync --server`, `scp -t`/
`scp -f`.

### 5. Per-step capsule context refactor (D2) -- DONE

Capsule retains per-step policy (declared peer set, trust anchors,
upstream dial, host-key pinning). The front owns the container-facing
listener and SSH endpoint; the capsule's `BridgePeer` dials the real
peer. Per-peer raw TCP forwarder (`sshforward.go` `serve`/`handle`/
`splice`) is retained but retired.

### 6. In-container agent socket removal

Remove the ADR-025 `SSH_AUTH_SOCK` injection and agent proxy. Container
presents `none` to the front. Eliminates the in-container signing oracle.

### 7. Synthetic container ssh_config + known_hosts -- DONE (run path)

Per-step SSH trust volumes deliver `ssh_known_hosts` and `ssh_config` at
`/etc/ssh` via read-only named volumes. `planTrustVolumes` batches CA +
SSH volumes in a single `SeedVolumes` call. Deploy path deferred (SSH
peers rejected).

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
2. `STRIKE_PEER` token + front dispatch table -- **DONE**
3. Front termination (run-level host key) + capsule context refactor --
   **DONE**; connection lifecycle: each side closes what it initiated,
   no teardown timer
4. SSH server/client with D1 command allowlist; agent in the front;
   synthetic container known_hosts -- **DONE**
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
