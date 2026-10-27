# ADR 0003: Binding journal format and replication

- Status: accepted
- Date: 2026-10-27
- Related: [ADR 0001](0001-protocol.md), [ADR 0002](0002-token-format.md)

## Context and problem statement

An authority issues a token only for an identity whose current binding names
the requesting key and whose callbacks succeed. Bindings change rarely
(enrollment, restore, migration, decommissioning) and every change is an
administrative approval. Several authority instances run independently, at
different places, without a shared database and without a leader; each must
be able to issue on its own and survive the loss of all others.

The journal also grows with every token request. It must be possible to
shorten it without giving up the rule that no instance can invent a binding.

This ADR fixes how bindings are recorded and approved, how the current state
is derived, how instances replicate the journal, and how it is shortened.
Replication and compaction are built in a later step; their format is fixed
here so that the stored data does not change when they arrive.

## Decision drivers

- Every binding change carries the approval of administrators, verified by
  every instance before it is stored — whether it arrives through the write
  API or from another instance. A compromised instance can relay valid
  events but cannot invent one.
- Multiple approvals (four-eyes) without multisig support in the signature
  format.
- Signatures that administrators can make with tools they already have,
  including hardware security keys.
- Deterministic convergence: the same set of events gives the same state on
  every instance, regardless of arrival order, also after a partition.
- Append-only history up to the latest checkpoint; the journal is also the
  backup.
- Bounded growth: the journal can be shortened without trusting the instance
  that shortens it.
- No leader, no quorum, no shared database; a new instance is built from a
  copy.
- The replication code is a separable package that other systems can reuse.

## Considered options

1. **Signed, append-only event journal in SQLite per instance, replicated by
   push with an on-disk outbox and shortened through checkpoints; approvals
   as SSH signatures with a threshold from a static registry** (chosen).
2. **Configuration in a git repository, merge request as approval.** Makes
   the git server part of the trust base and of every restore, including its
   own.
3. **Consensus store (Raft: etcd, Consul).** Needs a majority; an isolated
   site could not change bindings and, depending on the setup, not even read
   them.
4. **Multisig in the signature format.** SSH signatures have none; script
   multisig in other formats needs an interpreter in the authority.

## Decision outcome

Chosen option 1.

### Events

| Kind | Signed by | Content |
| --- | --- | --- |
| `binding.set` | administrators | identity, key fingerprint, checks, epoch |
| `binding.revoked` | administrators | identity, epoch |
| `observation.<result>` | the instance | an issuance or a refusal, see below |
| `checkpoint` | the instance | the projection with the administrators' signatures, and the coverage, see below |

Only binding events change the projection, on their own or inside a
checkpoint. Observations are records.

### Binding event

Wire form (write API body and journal body):

```json
{
  "v": 1,
  "kind": "binding.set",
  "trust_domain": "example.com",
  "identity": "host1.example.com",
  "epoch": 3,
  "key": "SHA256:<daemon key fingerprint, ADR 0001>",
  "checks": [
    {"type": "tailnet", "target": "host1.tailnet.example.com"},
    {"type": "net", "target": "198.51.100.0/24"}
  ],
  "signatures": ["-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----\n"]
}
```

- `identity` and `tailnet` targets are lower-case DNS names; `ip` targets
  are IP addresses in canonical form, optionally with `:port` (IPv6 as
  `[addr]:port`); `net` targets are masked prefixes.
- `binding.set` needs at least one check; checks are unique.
- `binding.revoked` carries neither key nor checks.
- `epoch` starts at 1.

### Canonical form

Administrators sign a canonical text, not the JSON:

```
ergosum binding v1
kind binding.set
trust-domain example.com
identity host1.example.com
epoch 3
key SHA256:<fingerprint>
check net 198.51.100.0/24
check tailnet host1.tailnet.example.com
```

One `name value` line per field in this order, LF line endings, a final LF,
checks sorted by type and then target. A revocation ends after `epoch`.
Validation forbids whitespace and line breaks inside values, so a value can
never forge a line. The text is meant to be read by the person who signs it.

The **event hash** is the hex SHA-256 of the canonical text. It ignores the
signatures: the same content with other signatures is the same event.

The trust domain is part of the signed text, so an event approved for one
deployment is worthless in another that trusts the same administrator keys.

### Signatures and approvals

- Signature format: SSHSIG as produced by `ssh-keygen -Y sign`, namespace
  **`ergosum-binding`**, hash `sha512` or `sha256`. RSA signatures with
  SHA-1 are rejected. Signatures from security keys (`sk-ssh-ed25519`,
  `sk-ecdsa-sha2-nistp256`) must assert user presence.
- Signatures are made separately (any order, any machine) over the canonical
  text and merged into one event before it is written. Instances never hold
  half-approved events.
- The **registry** is static configuration on every instance and the trust
  root. It names administrator keys and, per event kind, a threshold and the
  allowed keys:

  ```yaml
  registry:
    admins:
      alice: "ssh-ed25519 AAAA... alice@example.com"
      bob:   "sk-ssh-ed25519@openssh.com AAAA... bob@example.com"
    approvals:
      binding.set:     {threshold: 2, keys: [alice, bob]}
      binding.revoked: {threshold: 1, keys: [alice, bob]}
  ```

- An event is accepted only if **every** signature verifies over its
  canonical text and comes from a key allowed for its kind, no key signs
  twice, and the number of distinct signers reaches the threshold. A
  signature over another epoch (or any other content) does not verify and
  rejects the event.

### Epochs and the ordering rule

The epoch orders the bindings of one identity. A new binding (re-enrollment,
restore, migration) or a revocation uses the current epoch plus one.

Of two binding events for the same identity, the one that **wins** is:

1. the one with the higher epoch;
2. at equal epochs, the revocation;
3. otherwise the one with the lexicographically smaller event hash.

The projection of an identity is the winner among all its accepted binding
events. The rule is a total order, so the projection depends only on the set
of events, not on their arrival order: two events written at different
instances during a partition converge everywhere after replication.

The write API (`POST /v1/bindings` on the authority's TLS listener, ADR 0001)
answers `201` with origin, sequence number and hash. It rejects invalid
content or insufficient approvals with `422 rejected`, and an event that
would not win against the current projection (lower epoch, or same epoch
and losing) with `409 conflict`. Re-submitting an accepted event is
acknowledged with `200` without storing it again. `GET
/v1/bindings/<identity>` returns the projection, including the current
epoch. Through ingest, every verified event is stored, and the rule decides.

### Observations

An instance records the outcome of a token request that verifies against
a bound key as `observation.issued`, `observation.key_duplicate`,
`observation.wrong_location` or `observation.replay`. The body is a signed
envelope (ADR 0001,
context `ergosum/v1/observation`) made with the instance key, containing
instance, kid, identity, epoch, request ID, presented key, remote address,
per-check outcomes, token ID and reason. For `key_duplicate` it contains the
daemon's signed `no_open_request` response as evidence, verifiable with the
bound key alone.

Observations never set or end a binding. Only what the current
configuration authenticates enters the journal: binding events with the
approvals the registry demands, and observations of requests signed by the
key that the identity's binding names. Refusals of requests that do not
verify that way (`unknown_identity`, `foreign_key`) can be caused by anyone
with any number of names; they count in the metric and reach the audit log
within an overall limit (60 lines per minute), but never the journal.
`wrong_location` and `replay` can be repeated at will by a holder of the key
and are journaled once per identity and minute; `issued` and
`key_duplicate` always.

### Checkpoints and compaction

Observations add an event for every token request, and superseded binding
events would stay forever. A **checkpoint** records the complete current
state, so that the events it covers can be deleted.

A checkpoint is an event of kind `checkpoint`, written by an instance into
its own journal and replicated like any other event. Its body is a signed
envelope (ADR 0001, context `ergosum/v1/checkpoint`) made with the instance
key:

```json
{
  "v": 1,
  "type": "checkpoint",
  "trust_domain": "example.com",
  "instance": "authority-a",
  "kid": "<kid of the instance key>",
  "created_at": "2026-10-27T20:00:00Z",
  "coverage": {"authority-a": 1207, "authority-b": 954},
  "bindings": [
    {"kind": "binding.set", "identity": "host1.example.com", "epoch": 3, "...": "..."},
    {"kind": "binding.revoked", "identity": "host2.example.com", "epoch": 2, "...": "..."}
  ],
  "state_hash": "<hex SHA-256>"
}
```

- `bindings` is the projection when the checkpoint is written: for every
  identity its winning event, revocations included, verbatim with the
  administrators' signatures.
- `coverage` names, per origin, the highest sequence number up to which the
  instance has ingested every event of that origin — stored, or acknowledged
  as a duplicate. The checkpoint **covers** the events at or below it.
- `state_hash` is the hex SHA-256 over one line `<identity> <epoch> <event
  hash>` per identity, sorted by identity, each ending in LF. Instances that
  hold the same binding events have the same state hash.

**The instance signature grants nothing.** It says which instance wrote the
checkpoint and when. Every contained binding event is verified against the
local registry and trust domain, exactly as the write API does. A
compromised instance can therefore write a checkpoint that omits events, but
not one that adds a binding. Revocations stay in the checkpoint as the
winner of their identity: without them, an older, validly signed
`binding.set` could be replayed and would win again.

**Writing.** Every instance writes a checkpoint on a schedule (default:
daily) and on `ergosum journal checkpoint`. It needs the unsealed instance
key, as issuing does.

**Ingest.** A foreign checkpoint is verified against the instance key of its
origin, and each of its binding events as above; if one fails, the whole
checkpoint is rejected and raised as an alarm, as for a stale registry. Then
its binding events are applied under the ordering rule. The projection is
the winner of a set, so this is a union: an instance that missed a binding
event gets it with the next checkpoint of any peer. A foreign checkpoint
never causes a deletion.

**Compaction.** An instance deletes an event only if

1. its own latest checkpoint covers the event,
2. every configured peer has acknowledged both the event and that
   checkpoint, and
3. the retention for its kind has passed and, if an archive is configured,
   the event has been exported.

| Events | Default retention |
| --- | --- |
| observations except `key_duplicate` | 90 days |
| `observation.key_duplicate` | unlimited |
| binding events | unlimited |
| checkpoints | until a newer checkpoint of the same origin is covered |

A retention for binding events removes the history of bindings, not the
bindings: the winner of every identity lives on in the checkpoint. After
compaction the projection is the `bindings` of the latest own checkpoint
plus the remaining binding events, under the ordering rule.

An event that ingest rejects stops the coverage of its origin there. The
instance raises an alarm and does not compact that origin past the gap.

**Archive.** `ergosum journal export` writes events as JSON lines
(`origin`, `seq`, `kind`, `hash`, `body`) to the configured archive
directory. The archive needs no trust in whoever stores it: observations and
checkpoints are signed by their instance, binding events by administrators,
and gaps in the sequence numbers of an origin are visible.

Rejected alternatives:

- **A checkpoint that states the projection without the administrators'
  signatures.** Smaller, but anyone with the instance key could add bindings
  through it.
- **A checkpoint approved by administrators.** Safe, but routine maintenance
  would need administrators; no automatic compaction.
- **Expiring observations without a checkpoint.** Leaves superseded binding
  events in place and gives a rebuilt instance no complete state to start
  from.

### Storage

One SQLite database per instance (pure Go driver, no cgo), WAL mode,
`synchronous=FULL`.

```sql
events   (origin TEXT, seq INTEGER, kind TEXT, identity TEXT, epoch INTEGER,
          hash TEXT, body BLOB, recorded_at TEXT, PRIMARY KEY (origin, seq))
bindings (identity TEXT PRIMARY KEY, kind, epoch, key, checks, hash, origin, seq)
meta     (key TEXT PRIMARY KEY, value TEXT)   -- schema_version, trust_domain, next_seq
coverage   (origin TEXT PRIMARY KEY, seq INTEGER)  -- ingested without gaps
compaction (origin TEXT PRIMARY KEY, seq INTEGER)  -- may be deleted up to here
```

- `origin` is the instance that first recorded the event, `seq` its local
  sequence number. `(origin, seq)` identifies an event across instances.
- Sequence numbers are never reused. The next one is kept in `meta`, not
  derived from the remaining rows, which compaction may have removed.
- Triggers abort every `UPDATE` on `events`, and every `DELETE` of an event
  above the `compaction` frontier, so not even a bug in compaction can delete
  an uncovered event. The frontier is the coverage of the latest own
  checkpoint that every peer has acknowledged.
- Binding event hashes are unique.
- `bindings` is the projection, updated in the same transaction as the
  event; it can be recomputed at any time from the latest own checkpoint and
  `events`.
- The journal is pinned to its trust domain on creation.
- Schema version 1 has no checkpoints and forbids every `DELETE`. Version 2
  adds `next_seq`, `coverage`, `compaction` and the conditional trigger; an
  instance migrates on start without touching existing events. A checkpoint
  is stored with an empty `identity` and epoch 0.

### Replication

Push with an on-disk outbox, idempotent ingest, pull for catch-up. No
leader, no quorum.

- **Peers** are configured per instance with URL and key fingerprint, and
  the instance key of every peer, which also verifies that peer's
  observations.
- **Transport**: mutual TLS with the instance keys, pinned as in ADR 0001.
  No bearer tokens.
- **Outbox**: per peer, a cursor over the local insertion order of `events`
  (`peer_cursor(peer, last_acked)`). Every stored event, own or received, is
  pushed to every peer that has not acknowledged it, so events also travel
  through a third instance. The outbox lives on disk because the events do.
  Compaction waits for these cursors.
- **Push**: `POST /v1/journal/ingest` with a batch of events in insertion
  order (`origin`, `seq`, `kind`, `identity`, `epoch`, `hash`, `body`). The
  peer answers with the last position it accepted; the cursor advances.
- **Ingest** verifies every event before storing it: binding events against
  the local registry and trust domain, exactly as the write API does;
  observations against the instance key of their origin; checkpoints as
  described above. Events are idempotent by `(origin, seq)`; the same
  `(origin, seq)` with another hash is rejected and raised as an alarm. A
  binding event whose hash is already stored under another origin is
  acknowledged without storing it again. Observations and checkpoints at or
  below the instance's coverage are acknowledged without storing them, so a
  peer cannot push deleted events back; binding events are ingested as
  always.
- **Sync**: `GET /v1/journal/events?after=<position>` pages through a
  peer's journal; `ergosum journal sync --from <peer>` pulls it with the
  same verification. A new or rebuilt instance starts with a sync and then
  receives pushes. If `after` lies below the peer's compaction frontier, the
  page starts with the checkpoint that compaction relied on, followed by the
  remaining events; the receiver ingests the checkpoint and raises its
  coverage to the checkpoint's where that is higher. With several `--from`,
  the instance takes the union of what the peers deliver.
- **Metrics**: outbox depth and age of the oldest unacknowledged event per
  peer; coverage and compaction frontier per origin; age of the latest own
  checkpoint. The ops listener (ADR 0001) also reports the state hash, so
  monitoring can compare instances once replication has settled.
- **Package boundary**: the replication package knows only `(origin, seq,
  kind, hash, body)`, a store interface and a verifier callback. Coverage,
  the compaction frontier and the checkpoint-first sync page belong to the
  package; writing, verifying and applying a checkpoint are callbacks. It
  does not import ergosum's event types and can be moved to a library of its
  own.

## Consequences

**Good**

- Bindings need administrator signatures everywhere; a compromised instance
  can refuse service and report false observations, but cannot bind or
  revoke.
- Every instance holds the complete state and the history since its last
  compaction; any copy rebuilds the others.
- The ordering rule makes convergence a property of the data, not of the
  network.
- The journal can be shortened without trusting the instance that does it:
  a checkpoint carries the administrators' signatures, not the instance's
  word.
- Checkpoints double as anti-entropy for bindings: an instance that missed a
  binding event gets it with the next checkpoint of any peer, and the state
  hash shows divergence.
- Administrators sign with `ssh-keygen`, including FIDO keys, and can read
  what they sign.

**Bad**

- The registry is static: adding or removing an administrator is a
  deployment to every instance, and a stale registry on one instance rejects
  events the others accept until it is updated.
- Revocation is not instant across instances; it takes effect at each
  instance when the event arrives there, bounded by the token lifetime
  afterwards.
- Compaction waits for every configured peer. A peer that is gone for good
  must be removed from the configuration, or the journal keeps growing.
- History beyond its retention exists only in the archive, if one is
  configured.
- A rebuilt instance relies on its sync peer not to omit binding events
  until the next checkpoint of an honest peer arrives. Syncing from several
  peers narrows that to the case where all of them omit the same event.
- A checkpoint repeats every binding with its signatures, roughly a kilobyte
  per identity; only the latest checkpoint of each origin is kept.
- The canonical text and the SSHSIG namespace are a compatibility promise:
  changing either needs a new canonical version line.
