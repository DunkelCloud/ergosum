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

This ADR fixes how bindings are recorded and approved, how the current state
is derived, and how instances replicate the journal. Replication itself is
built in a later step; its format is fixed here so that the stored data does
not change when it arrives.

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
- Append-only history; the journal is also the backup.
- No leader, no quorum, no shared database; a new instance is built from a
  copy.
- The replication code is a separable package that other systems can reuse.

## Considered options

1. **Signed, append-only event journal in SQLite per instance, replicated by
   push with an on-disk outbox; approvals as SSH signatures with a threshold
   from a static registry** (chosen).
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

Only binding events change the projection. Observations are records.

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

An instance records the outcome of each token request as
`observation.issued`, `observation.key_duplicate`,
`observation.wrong_location`, `observation.foreign_key` or
`observation.unknown_identity`. The body is a signed envelope (ADR 0001,
context `ergosum/v1/observation`) made with the instance key, containing
instance, kid, identity, epoch, request ID, presented key, remote address,
per-check outcomes, token ID and reason. For `key_duplicate` it contains the
daemon's signed `no_open_request` response as evidence, verifiable with the
bound key alone.

Observations never set or end a binding. `foreign_key` and
`unknown_identity` can be caused by anyone and are rate-limited (one per
identity and minute) before they reach the journal.

### Storage

One SQLite database per instance (pure Go driver, no cgo), WAL mode,
`synchronous=FULL`.

```sql
events   (origin TEXT, seq INTEGER, kind TEXT, identity TEXT, epoch INTEGER,
          hash TEXT, body BLOB, recorded_at TEXT, PRIMARY KEY (origin, seq))
bindings (identity TEXT PRIMARY KEY, kind, epoch, key, checks, hash, origin, seq)
meta     (key TEXT PRIMARY KEY, value TEXT)   -- schema_version, trust_domain
```

- `origin` is the instance that first recorded the event, `seq` its local
  sequence number. `(origin, seq)` identifies an event across instances.
- Triggers abort every `UPDATE` and `DELETE` on `events`.
- Binding event hashes are unique.
- `bindings` is the projection, updated in the same transaction as the
  event; it can be recomputed from `events` at any time.
- The journal is pinned to its trust domain on creation.

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
- **Push**: `POST /v1/journal/ingest` with a batch of events in insertion
  order (`origin`, `seq`, `kind`, `identity`, `epoch`, `hash`, `body`). The
  peer answers with the last position it accepted; the cursor advances.
- **Ingest** verifies every event before storing it: binding events against
  the local registry and trust domain, exactly as the write API does;
  observations against the instance key of their origin. Events are
  idempotent by `(origin, seq)`; the same `(origin, seq)` with another hash
  is rejected and raised as an alarm. A binding event whose hash is already
  stored under another origin is acknowledged without storing it again.
- **Sync**: `GET /v1/journal/events?after=<position>` pages through a
  peer's journal; `ergosum journal sync --from <peer>` pulls it with the
  same verification. A new or rebuilt instance starts with a sync and then
  receives pushes.
- **Metrics**: outbox depth and age of the oldest unacknowledged event per
  peer.
- **Package boundary**: the replication package knows only `(origin, seq,
  kind, hash, body)`, a store interface and a verifier callback. It does not
  import ergosum's event types and can be moved to a library of its own.

## Consequences

**Good**

- Bindings need administrator signatures everywhere; a compromised instance
  can refuse service and report false observations, but cannot bind or
  revoke.
- Every instance holds the full history; any copy rebuilds the others.
- The ordering rule makes convergence a property of the data, not of the
  network.
- Administrators sign with `ssh-keygen`, including FIDO keys, and can read
  what they sign.

**Bad**

- The registry is static: adding or removing an administrator is a
  deployment to every instance, and a stale registry on one instance rejects
  events the others accept until it is updated.
- Revocation is not instant across instances; it takes effect at each
  instance when the event arrives there, bounded by the token lifetime
  afterwards.
- Observations make the journal grow with every issuance; pruning or
  archiving them needs a later decision (bindings are small and never
  pruned).
- The canonical text and the SSHSIG namespace are a compatibility promise:
  changing either needs a new canonical version line.
