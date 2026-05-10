# ADR-024: SSH Peer Server-Trust Enforcement

## Status

Accepted.

## Scope

This ADR concerns enforcement of the SSH server-trust dimension of
ADR-022's typed peer list: rendering the typed `known_hosts`
entries into a file the container can use for strict-host-key
checking. It does not cover SSH client identity (private keys,
ssh-agent socket forwarding); per ADR-007, server identity and
client identity are asymmetric and arrive through separate
mechanisms. Client-identity enforcement is the subject of a
separate ADR.

## Context

ADR-022 established the typed peer list as the network opt-in
surface and explicitly deferred Phase-2 enforcement -- per-peer
mounts, ssh-agent forwarding, egress filtering -- "until a
concrete enforcement story is needed". The first such story has
now arrived: a step that needs to clone or pull from an
SSH-accessed git server cannot work effectively without OpenSSH's
strict-host-key checking, and strict-host-key checking requires
the server's host key to be available to the client at run time.

Currently, the typed `known_hosts` entries on `#SSHPeer` flow into
the signed deploy attestation but never reach the step container.
A lane author who declares a peer with `known_hosts` for
`git@git.example.com` cannot actually run `git clone` -- the
container's ssh has no way to know the server's host key, so
strict-host-key checking either fails the connection or, worse if
configured loosely outside strike, accepts any key on first use.

## Decision

For every container execution where the active peer list contains
at least one `#SSHPeer`, strike performs the following before the
container starts:

- Renders the typed entries into an OpenSSH-format `known_hosts`
  document. Each line is `<formatted_host> <key_type>
  <base64_key>\n`. `<formatted_host>` is `<host>` when no port is
  present and `[<host>]:<port>` when a port is present. Lines are
  sorted lexicographically by `(formatted_host, key_type, key)`
  so the output is byte-deterministic.
- Writes the document to a per-execution scratch file on the host.
- Bind-mounts that file read-only at `/etc/ssh/ssh_known_hosts`
  inside the container.
- Adds a single environment variable that overrides any
  image-default ssh configuration for git operations:

      GIT_SSH_COMMAND=ssh -o StrictHostKeyChecking=yes \
                          -o UserKnownHostsFile=/etc/ssh/ssh_known_hosts \
                          -o GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts \
                          -o PasswordAuthentication=no

The scratch file is removed when the container exits. The mount
and the env addition do not appear when no SSH peer is declared;
the existing `--network=none` / `--network=bridge` semantics from
ADR-022 are unchanged.

This applies to every container code path in strike: run-step
execution, state-capture execution, Kubernetes deploy methods,
and custom deploy methods. Doing it in three of the four would
create a "works for run, mysteriously fails for deploy" surprise
that is worse than no enforcement. The registry deploy method
(`registry.CopyImage`) does not run a container and is therefore
out of scope.

## Consequences

- Lane authors who declare an SSH peer get a working `git clone`
  / `git pull` over SSH without ad-hoc workarounds. The
  `known_hosts` entries they typed into the lane are exactly
  what the container enforces. An external verifier reading the
  signed attestation can confirm post-hoc that the typed claim
  and the runtime trust agreed.
- Image authors are free to ship their own `ssh_config`; the
  `GIT_SSH_COMMAND` injection bypasses it for git, and the
  bind-mounted `/etc/ssh/ssh_known_hosts` is the system-wide
  default for non-git ssh tools that consult it.
- The scratch file is host-side ephemeral and contains only
  public host-key data. It is not part of any artifact and not
  committed.
- A step image whose root filesystem does not already have
  `/etc/ssh/` is handled by the container runtime: the runtime
  creates the bind-mount target during container start, before
  the `--read-only` flag takes effect on the upper layer. If a
  particular image cannot accommodate the mount, that surfaces as
  a clear container-start error, not as a silent loss of
  enforcement.
- When the companion ADR for SSH client identity lands, the two
  arrive at the same container through orthogonal mechanisms (a
  `known_hosts` mount for server trust, an agent socket or a
  file-based key for client identity), preserving ADR-007's
  asymmetry.
- The runtime schema is unchanged. The `#SSHPeer` and
  `#KnownHostEntry` definitions already carry exactly the data
  this enforcement consumes; the lane author's surface is
  identical to before, only the runtime behaviour differs.

## Principles

- Peers are declared (now also enforced for the SSH server-trust
  dimension)
- Identity is asymmetric (server identity is enforced here;
  client identity stays separate)
- No root (the file is bind-mounted read-only with no privileged
  operation needed)
- Code is liability (one rendering function, one mount, one env
  injection; no SSH client logic in strike)
