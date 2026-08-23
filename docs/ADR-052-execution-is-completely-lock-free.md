# ADR-052: Execution is completely lock-free

## Status

Accepted. Generalizes the concurrency model the DAG scheduler already
implements (one write-once record per step, published through atomic
pointers, joined by a drain barrier) from the walk to the whole
executor. Consistent with
[ADR-028](ADR-028-step-container-egress-mediation.md) (per-step
resolver and mediator, whose capture records feed attestation),
[ADR-033](ADR-033-ssh-peer-egress-and-unified-mediation.md) and
[ADR-038](ADR-038-protocol-mediated-ssh.md) (the front/bridge
lifecycle this decision restructures). Supersedes the concurrency
guidance in `docs/DEVELOPMENT.md` section 3.8, which is rewritten to
state this decision.

## Context

The executor coordinates concurrent work in two ways today. The step
walk is lock-free: every coordination word is monotone (an in-degree
that only decrements, a failure flag that only sets, a record pointer
that publishes once) and the only blocking construct is a drain
barrier. Everything else -- connection and query records, the SSH
client set, first-connection identity captures, the shared
leaf-certificate cache, and three lifecycle states -- is guarded by
seven mutexes.

A concurrency audit of the module surveyed the defect class the race
detector cannot see -- blocking calls nothing can interrupt -- and
found exactly one lock involved: capsule stop holds its state mutex
across the serve-group wait, turning one blocked connection into a
blocked lifecycle. No mutex-guarded structure in the module needs
mutual exclusion in principle: every one is either a capture that has
a natural single owner, a first-wins publication, a closed-world
cache, or a monotone lifecycle.

Mutual exclusion has a cost profile this project cannot observe
structurally: its correctness depends on every accessor taking the
lock (a convention, not a shape), its critical sections can be held
across blocking calls for unbounded time, and `-race` certifies
neither property. Joins and publications have the opposite profile:
there is no region to hold, the states are monotone, and the
happens-before edges are exactly what `-race` models and what
`testing/synctest` can drive deterministically.

## Decision

### D1 -- No mutual exclusion in production code

Production code (`cmd/` and `internal/`, excluding `*_test.go` and
`*.gen.go`) declares no mutual-exclusion primitive: `sync.Mutex`,
`sync.RWMutex`, `sync.Map`, `sync.Cond`, and `sync.Once` (including
`sync.OnceFunc`, `sync.OnceValue`, `sync.OnceValues`) are banned.
Shared state is coordinated only by: single ownership (exactly one
goroutine writes), write-once publication through `sync/atomic`,
ownership transfer through channels, and completion joins through
`sync.WaitGroup` or `golang.org/x/sync/errgroup`.

The boundary is stated honestly: channels, `WaitGroup` parking, and
`errgroup` internally traverse runtime locks (`runtime.hchan.lock`,
the semaphore's `semaRoot.lock`, the `Mutex` inside `sync.Once`).
Those are constant-size, nanosecond-scale critical sections over
runtime state that application code cannot hold, extend, or observe.
This decision governs strike's coordination topology -- no
application-defined critical section exists -- not the machine room.
Tests and `tools/` are out of scope: test doubles legitimately record
concurrent calls under a lock, and neither is part of the attested
runtime.

### D2 -- Coordination is ownership; joins wait only downward

Every blocking coordination point in production code is a join on
work the blocker owns: a drain barrier over its own goroutines, a
receive on a channel its worker closes, a load of a pointer its
producer publishes. The ownership graph is acyclic by construction
(runtime -> step -> capsule -> serve group -> handler), so joins
cannot deadlock among themselves; a join can only wait on a worker
that has not finished. The companion obligation is therefore on the
workers: every blocking call a worker makes is bound to its context,
so that cancellation is an unblocking event. A join whose worker
cannot be cancelled is a defect of the worker, not of the join.

### D3 -- Capture collections have one owner; Records is final after Stop

Each record-collecting component (mediator connection records,
resolver query records, SSH bridge records) appends through exactly
one collector goroutine inside the component's serve group, fed by a
channel from producers that the serve group joins. Arrival order is
preserved, because the records enter the attestation. `Records()` is
defined only after `Stop` has returned; a capsule's lifetime is its
step's lifetime -- it stops when the step's container is reaped, and
the lane-end sweep remains only as the backstop for steps that never
ran.

### D4 -- The certificate universe is closed at construction

The ephemeral CA issues the leaf certificate for every declared peer
SNI at construction; the leaf map is immutable afterwards and read
without coordination. The CA private key is discarded before the
constructor returns -- with a closed world there is nothing left to
sign, and the key-material window shrinks from the lane's duration to
the construction call. This encodes "peers are declared" in the data
structure: a lazy cache models an open world that the mediator's SNI
gate already forbids.

### D5 -- First-wins captures publish by compare-and-swap

A capture that keeps the first observed value (resolver-probe
identity, push-connection identity) is an atomic pointer published by
compare-and-swap from nil, loaded by its reader. No lock, no lost
update, and the first-wins semantics is the CAS semantics.

### D6 -- Dead lifecycle API is removed, not converted

A lifecycle method with no production caller is deleted together with
the state it guards, rather than converted to an atomic. Removal is
the default resolution; converting dead surface would preserve a
liability in a new costume.

### D7 -- Enforcement is a structural observation

`make lint` gains a gate that searches production Go for the banned
identifiers of D1 and requires zero findings. `-race` remains
mandatory but is not the certificate: the race detector cannot see a
lock held across an unbounded wait, which is precisely the class this
decision removes. If the textual gate ever proves too coarse, its
successor is a typed `go/analysis` checker in the house style; that
successor is tracked as owned follow-up work, not built speculatively.

## Consequences

- Seven mutexes leave production code; the expected net effect is a
  deletion, because two of the seven fall to API removal (D6), one to
  a closed-world data structure (D4), and the SSH client set to
  context binding rather than to a replacement structure.
- The `sync` import in production code shrinks to `WaitGroup`.
- `Records()` narrows its contract (D3); the deploy path reads records
  after stop, the run path stops each capsule at its step's end, and
  the tests that polled records against a live serve loop are
  rewritten against the final-after-Stop contract.
- `transport.New` takes the declared SNI set (D4); every constructor
  call site, tests included, is updated in the same change.
- Existing lock-free publication that is only implicitly correct is
  named and documented: the front's token dispatch map (built before
  the front starts, read-only afterwards) and the engine identity
  captured once at pre-flight. Neither changes behavior; both gain
  the publish-before-spawn statement their correctness rests on.
- `docs/DEVELOPMENT.md` section 3.8 is rewritten: the write-once
  preference becomes the rule, and the "reach for sync.Map if
  profiling shows contention" escape is removed.
- `docs/ADR-INDEX.md` gains this ADR's line.

## Alternatives considered

- **Literal lock-freedom.** Unattainable in Go: every channel
  operation takes `hchan.lock`, WaitGroup waiters park through a
  semaphore whose root is locked, and `sync.Once` carries a `Mutex`
  for its slow path. A decision that pretended otherwise would be
  false; D1 states the boundary instead.
- **Per-site lock-free containers.** A hand-rolled CAS-linked list
  would preserve the snapshot-during-serve contract, at the price of
  a bespoke concurrent structure in a security tool and a reversed
  order on a collection that feeds attestation. Rejected: code is
  liability, and the contract the structure would preserve exists
  only by accidental sequencing.
- **Actor goroutines for the SSH client set.** Rejected where a
  deletion path exists: the set exists only to compensate for a dial
  that is not bound to its context; binding the dial removes the set.
- **Keeping the `sync.Map` escape hatch.** Rejected; the escape was a
  hedge against contention that per-owner records make unreachable.

## Principles

- **Enforcement is structural.** Correct concurrency is a property a
  gate can observe (zero banned declarations, green `-race`), not a
  discipline every accessor must remember.
- **Code is liability.** Two mutexes fall to deletion, one to a
  simpler data structure; the replacement for the rest is ownership,
  not a cleverer lock.
- **Peers are declared.** The closed peer world reaches the CA's data
  structure: the certificate set is fixed at construction because the
  peer set is.
- **Runtime is attested.** Capture records keep their arrival order
  through a single owner; what enters the attestation is what one
  goroutine wrote, in the order it observed.
