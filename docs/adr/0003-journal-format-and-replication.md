# ADR 0003: Binding journal format and replication

- Status: proposed
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

Besides, the instance that records an event signs its position: origin,
sequence number, kind and hash (see Replication, Event signatures). That
signature says where the event was recorded; it grants nothing.

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
  SHA-1 and DSA keys are rejected; RSA admin keys need at least 2048 bits,
  and certificates are not accepted as admin keys. Signatures from security
  keys (`sk-ssh-ed25519`, `sk-ecdsa-sha2-nistp256`) must assert user
  presence.
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
  rejects the event. An event with more signatures than the kind has allowed
  keys is refused before any of them is verified.

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
content or insufficient approvals with `422 rejected`, and an event whose
epoch is not above the current one with `409 conflict` — also an event that
would win at the same epoch, such as a revocation. An administrator's change
is made against the binding they saw; if another change took its epoch
meanwhile, the change must be made anew, so that none replaces another one
unnoticed. Re-submitting an accepted event is acknowledged with `200`
without storing it again. Through ingest, every verified event is stored,
and the ordering rule decides: two changes written at different instances
before either has the other still converge.

### Read API

On the same listener, for administrator tooling and for daemons:

- `GET /v1/bindings/<identity>` returns the projection of one identity
  (`404` if it has none), including the current epoch, and `signed_by`: the
  administrators who approved the winning event, by their registry name, or
  by key fingerprint for a key the registry no longer knows.
- `GET /v1/bindings` returns the projection of every identity, ordered by
  identity, the trust domain, and per event kind the threshold and the
  allowed administrators with their key fingerprints, so that tooling can
  tell when an event has enough signatures:

  ```json
  {
    "v": 1,
    "trust_domain": "example.com",
    "approvals": {
      "binding.set": {"threshold": 2, "admins": {"alice": "SHA256:...", "bob": "SHA256:..."}},
      "binding.revoked": {"threshold": 1, "admins": {"alice": "SHA256:...", "bob": "SHA256:..."}}
    },
    "bindings": [
      {"identity": "host1.example.com", "kind": "binding.set", "epoch": 3,
       "key": "SHA256:...", "checks": [{"type": "tailnet", "target": "host1.tailnet.example.com"}],
       "hash": "...", "origin": "authority-a", "seq": 12}
    ]
  }
  ```

Bindings and administrator key fingerprints are no secret, and the
per-identity read already showed every binding to whoever knew the name.
The list saves the guessing; it shows the inventory to every machine that
reaches the listener.

### Observations

An instance records the outcome of a token request that verifies against
a bound key as `observation.issued`, `observation.key_duplicate`,
`observation.wrong_location`, `observation.replay` or
`observation.misdirected`. The body is a signed
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
Rejected binding writes share that limit.
`wrong_location`, `replay` and `misdirected` can be repeated at will by a
holder of the key and are journaled once per identity and minute; `issued` and
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
daily, if the journal changed since the last one) and on `ergosum journal
checkpoint`. It needs the unsealed instance key, as issuing does.

**Ingest.** A foreign checkpoint is verified against the instance key of its
origin (signature, `kid`, `instance` equal to the origin, trust domain), and
each of its binding events as above; the bindings must name every identity
at most once, and the state hash must match them. If anything fails, the
whole checkpoint is rejected and raised as an alarm, as for a stale
registry. Then its binding events are applied under the ordering rule. The
projection is the winner of a set, so this is a union: an instance that
missed a binding event gets it with the next checkpoint of any peer. A
foreign checkpoint never causes a deletion.

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

Compaction runs on the checkpoint schedule and on `ergosum journal compact`:
it exports to the archive if one is configured, raises the frontier to the
newest own checkpoint every peer has acknowledged, and deletes what the
frontier, the peers' cursors and the retention allow.

**Archive and export.** Events are written as JSON lines (`origin`, `seq`,
`kind`, `hash`, `body`, the body as the stored JSON, and `sig`, the position
signature). Before compaction, and on `ergosum journal export -archive`, the
instance writes the events not yet archived to a new file in the configured
archive directory; only archived events may then be deleted. `ergosum
journal export` streams the whole journal, for example to a recovery copy;
it reads the journal in batches, so a slow reader does not hold up
issuance. An export needs no trust in whoever stores it: every position is
signed by its origin, observations and checkpoints by their instance,
binding events by administrators, and gaps in the sequence numbers of an
origin are visible.

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
          hash TEXT, body BLOB, recorded_at TEXT, pos INTEGER UNIQUE, sig BLOB,
          PRIMARY KEY (origin, seq))
bindings (identity TEXT PRIMARY KEY, kind, epoch, key, checks, hash, origin, seq, body)
meta     (key TEXT PRIMARY KEY, value TEXT)   -- schema_version, trust_domain, instance,
                                              -- next_seq, next_pos, compacted_pos,
                                              -- frontier_pos, exported_pos
coverage    (origin TEXT PRIMARY KEY, seq INTEGER)  -- ingested without gaps
compaction  (origin TEXT PRIMARY KEY, seq INTEGER)  -- may be deleted up to here
peer_cursor (peer TEXT PRIMARY KEY, pos INTEGER)    -- acknowledged by a peer up to here
```

- `origin` is the instance that first recorded the event, `seq` its local
  sequence number. `(origin, seq)` identifies an event across instances.
- `pos` is the local insertion order, the order in which the instance
  forwards events; the next one is kept in `meta`, so positions are never
  reused either.
- Sequence numbers are never reused. The next one is kept in `meta`, not
  derived from the remaining rows, which compaction may have removed.
- Triggers abort every `UPDATE` on `events` except setting a missing `sig`
  once, and every `DELETE` of an event above the `compaction` frontier, so
  not even a bug in compaction can delete an uncovered event. The frontier is the coverage of the latest own
  checkpoint that every peer has acknowledged; it only rises, which another
  trigger enforces. `frontier_pos` is that checkpoint's position,
  `compacted_pos` the highest position compaction has deleted, and
  `exported_pos` the highest position written to the archive.
- `coverage` of an origin is the highest sequence number up to which every
  event of that origin has been stored or acknowledged; it advances over
  events stored contiguously.
- A binding event hash is unique per origin. The same event can be stored
  under several origins when it was written at several instances; it is one
  event for the ordering rule.
- `bindings` is the projection, updated in the same transaction as the
  event, with the body of the winning event for the next checkpoint; it can
  be recomputed at any time from the stored checkpoints and binding events.
- The journal is pinned to its trust domain and to its instance name on
  creation; a renamed instance would otherwise start a second origin in the
  same file.
- Schema version 1 has no checkpoints and forbids every `DELETE`. Version 2
  adds the positions, the position signatures, the counters in `meta`,
  `coverage`, `compaction`, `peer_cursor`, the body in `bindings` and the
  conditional triggers; an instance migrates on start without changing the
  content of existing events, and signs their positions once its key is
  unsealed. A checkpoint is stored with an empty `identity` and epoch 0.
- Times are stored as RFC 3339 in UTC with nine fractional digits, so that
  they compare correctly as text.

### Replication

Push with an on-disk outbox, idempotent ingest, pull for catch-up. No
leader, no quorum.

- **Peers** are configured per instance: every other instance of the trust
  domain with its name and public instance key, which pins its TLS key and
  verifies the positions of its events, its observations and its
  checkpoints, also when a third instance forwards them. A peer with a URL receives pushes, and compaction waits for
  its acknowledgments; a peer without URL is only known.
- **Transport**: a listener of its own (port 7435, ADR 0001) with mutual TLS
  and the instance keys, pinned as in ADR 0001; it accepts only configured
  peers. No bearer tokens.
- **Outbox**: per peer, a cursor over the local insertion order of `events`
  (`peer_cursor`). Every stored event, own or received, is pushed to every
  peer that has not acknowledged it, so events also travel through a third
  instance. The outbox lives on disk because the events do. Compaction waits
  for these cursors.
- **Page**: push and pull carry the same JSON page:

  ```json
  {
    "v": 1,
    "instance": "authority-a",
    "start": {"pos": 1180, "origin": "authority-a", "seq": 1207, "kind": "checkpoint", "hash": "...", "body": "...", "sig": "..."},
    "events": [{"pos": 1181, "origin": "authority-b", "seq": 954, "kind": "observation.issued", "hash": "...", "body": "<base64>", "sig": "<base64>"}],
    "last": 1181,
    "more": false
  }
  ```

  `pos` is the sender's position, `last` the position the page reaches,
  `start` present only as described under Sync. Receivers ignore unknown
  members. A page holds at most 256 events and stays within
  `replication.max_page_mib` (default 32 MiB), which every instance also
  enforces on what it receives; a single event, in practice a checkpoint,
  must fit into one page.
- **Event signatures**: `sig` is the origin's signature with its instance
  key (ADR 0001, context `ergosum/v1/event`) over the JSON array
  `[origin, seq, kind, hash]`; the hash covers the body. Ingest checks it
  with the configured key of the origin before anything else. Binding
  events carry it too, although the administrators' signatures alone
  decide whether they hold: without it, a peer could store a valid binding
  event under another instance's `(origin, seq)`, and the genuine event at
  that position would conflict at every instance and cut that instance off
  from replication in both directions. Sequence numbers and coverage above
  2^53 are rejected, so that no counter derived from them can overflow.
- **Push**: `POST /v1/journal/ingest` with a page. The peer answers
  `{"v": 1, "accepted": <position>}`, with `200` if it took the whole page
  and `422` and an `error` if it stopped at a rejected event; the cursor
  advances to `accepted`, never beyond the page. `413` refuses a page over
  the limit. `503` means ingest failed for a reason other than the event,
  such as the database or a canceled request: nothing more is acknowledged,
  no alarm is raised, and the sender retries with backoff. A `200` that does
  not accept the whole page counts as a failure as well.
- **Ingest** handles a page in order and verifies every event before
  storing it: its position signature, then binding events against the local
  registry and trust domain, exactly as the write API does; observations
  against the instance key of their origin; checkpoints as described above.
  Events are idempotent by `(origin, seq)`; the same `(origin, seq)` with
  another hash is rejected.
  Observations and checkpoints at or below the instance's coverage are
  acknowledged without storing them, so a peer cannot push deleted events
  back; binding events there are stored unless their hash is already
  known, so that no coverage claim can keep a valid binding event out.
  Above the coverage every verified event is stored, also a binding event
  stored under another origin before, so that forwarded streams have no
  gaps. Events of the instance's own origin that it no longer holds are
  acknowledged if compaction removed them; a rebuilt instance stores the
  others and continues its sequence numbers after them.
- **Equivocation**: an event at a position that holds another event, or a
  binding event its origin recorded under another sequence number, that
  verifies as well proves that its origin signed contradicting events. It is
  proof against the origin, not against the sender: ingest acknowledges and
  skips it, keeps the event it has, and raises an alarm (audit line with
  both hashes and the signature, metric per origin). Stopping there instead
  would let one compromised instance halt replication between all honest
  ones, revocations included. Instances may then hold different events of
  that origin at that position; for observations that only weakens the
  record, and binding events converge through the checkpoints. An
  equivocating instance must be taken out of service.
- **Rejection**: only an event that fails verification is rejected. Ingest
  stops at the first rejected event and acknowledges
  only what came before it, so the coverage of that origin stops there. The
  rejected event is never acknowledged: the sender keeps it in its outbox
  and retries with backoff, and compaction keeps it on the sender. The
  receiver raises an alarm (audit line at error level, metric per peer); the
  growing outbox shows on the sender.
- **Sync**: `GET /v1/journal/events?after=<position>&limit=<n>` pages
  through a peer's journal; `ergosum journal sync --from <peer>` makes the
  local instance pull it and ingest it with the same verification. A new or
  rebuilt instance starts with a sync and then receives pushes. If `after`
  lies below the peer's compaction frontier, every page up to the deleted
  positions starts with the checkpoint that compaction relied on, followed
  by the events that survived; the receiver ingests the checkpoint and
  raises its coverage to the checkpoint's where that is higher, its own
  sequence counter included. A pushed page starts the same way when the
  peer's cursor lies below the frontier, which happens only for a peer added
  after a compaction; the receiver then stores the checkpoint but does not
  take over its coverage. Only a sync, which an operator starts against a
  peer of their choice, does: a pushed claim could otherwise make the
  instance skip a third instance's observations or raise its sequence
  counter. Only the sender's own checkpoint can start a page. With several
  `--from`, the instance takes the union of what the peers deliver.
- **Metrics**: `machine_identity_journal_outbox_events` and
  `machine_identity_journal_outbox_oldest_age_seconds` per peer;
  `machine_identity_journal_coverage` and
  `machine_identity_journal_compaction_frontier` per origin;
  `machine_identity_journal_checkpoint_age_seconds`;
  `machine_identity_journal_rejected_total` per peer;
  `machine_identity_journal_compacted_events_total`. The ops listener also
  reports the state hash, coverage, frontier and outboxes
  (`GET /v1/journal/state`), so monitoring can compare instances once
  replication has settled.
- **Package boundary**: the replication package knows only `(origin, seq,
  kind, hash, body, sig)`, a store interface and callbacks: verifying an
  event (its `sig` included; an error marked invalid rejects it, any other
  is temporary), the kinds that are always ingested, the checkpoint kind and
  its coverage, the HTTP client per peer and the authentication of incoming
  requests. Coverage, the compaction frontier, the checkpoint-first page,
  the outbox, the bytes an origin signs, the limits on sequence numbers and
  page size, and the HTTP endpoints belong to the package; signing,
  writing, verifying and applying a checkpoint and deleting events stay
  with the journal. It depends on the standard library only and can be
  moved to a library of its own.

## Consequences

**Good**

- Bindings need administrator signatures everywhere; a compromised instance
  can refuse service and report false observations, but cannot bind or
  revoke, and cannot take another instance's place in the journal.
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
- Administrators sign with `ssh-keygen` or through their SSH agent,
  including FIDO keys, and can read what they sign.
- A change made against an outdated binding is refused at the write API
  instead of silently replacing the newer one.

**Bad**

- An administrator whose change lost its epoch to another one starts again.
- The list of every binding is readable by every machine that reaches the
  API listener.

- The registry is static: adding or removing an administrator is a
  deployment to every instance, and a stale registry on one instance rejects
  events the others accept until it is updated.
- Revocation is not instant across instances; it takes effect at each
  instance when the event arrives there, bounded by the token lifetime
  afterwards.
- Compaction waits for every configured peer. A peer that is gone for good
  must be removed from the configuration, or the journal keeps growing.
- One rejected event stops replication from that peer until the cause is
  fixed (a stale registry here, a forged event there); later events wait
  behind it, also those of other origins the peer forwards.
- A peer that an instance syncs from can, through the coverage of its
  checkpoint, make that instance skip other origins' observations up to the
  claimed coverage and raise its own sequence counter (up to 2^53). Binding
  events are always ingested, so this cannot keep a binding out; a pushed
  checkpoint's coverage does not count.
- Observations and checkpoints verify with the configured key of their
  origin. An instance keeps its key for the life of its name; a new key is a
  new instance name.
- A rebuilt instance must sync before it accepts writes: an event it
  records before would reuse a sequence number its peers know, and they
  reject it as a conflict.
- Ingest verifies against the current registry, also history and the
  bindings inside checkpoints. Once an administrator key leaves the
  registry, every binding event approved only with it fails verification,
  and a sync of a journal that still holds one stops there. Such bindings
  must be approved again by the remaining administrators, and the old
  events compacted away, before the key is removed.
- History beyond its retention exists only in the archive, if one is
  configured.
- A rebuilt instance relies on its sync peer not to omit binding events
  until the next checkpoint of an honest peer arrives. Syncing from several
  peers narrows that to the case where all of them omit the same event.
- A checkpoint repeats every binding with its signatures, roughly a kilobyte
  per identity and about 1.6 KB on the wire; only the latest checkpoint of
  each origin is kept. It must fit into one page: at the default of 32 MiB,
  that is about 20 000 identities, beyond which `max_page_mib` must grow on
  every instance.
- The canonical text and the SSHSIG namespace are a compatibility promise:
  changing either needs a new canonical version line.
