# ADR 0004: Releasing secrets without Vault

- Status: proposed
- Date: 2026-11-02
- Related: [ADR 0001](0001-protocol.md), [ADR 0002](0002-token-format.md), [ADR 0003](0003-journal-format-and-replication.md)

## Context and problem statement

With Vault, a machine gets its secrets after it has passed its checks: the
authority issues a token, Vault Agent logs in with it and renders the
secrets to tmpfs. Some secrets cannot wait for that or should not depend on
it: the configuration of a service on a machine without Vault, a secret
needed before Vault Agent runs, the repository password of the Vault nodes'
own backups. Such secrets end up in plain files on the disk, and with them
in every backup, image and copy of the machine.

This ADR lets a machine keep such a secret on its disk only in sealed form
(called *part A* below) and open it only after it has passed the checks of
its binding at enough authority instances, without Vault. Part A may lie in
backups and repositories: a copy of it elsewhere fails the place checks and
opens nothing. The authority stores nothing per machine and learns neither
part A nor the secret. The scheme follows Tang and Clevis.

## Decision drivers

- The authority learns neither part A nor the secret, keeps no state per
  machine, and the journal stays free of secrets (ADR 0003).
- Bound to the identity: a machine that passes its own checks gets nothing
  out of another machine's part A.
- Several instances with a threshold, k of n; only instances that can run
  every check of the identity count.
- Additive: no change to the messages of ADR 0001, the token of ADR 0002 or
  the journal of ADR 0003. Daemons and authorities of earlier versions keep
  working with those of this one.
- A new instance needs no change on the machines.
- Usable as a password command (`restic --password-command`,
  `RESTIC_PASSWORD_COMMAND`, `BORG_PASSCOMMAND`) without integration work.
- Standard building blocks: P-256 (as in ADR 0001), HKDF-SHA256,
  AES-256-GCM.

## Considered options

1. **McCallum-Relyea exchange with a key per identity and instance, k of n**
   (chosen).
2. **Part B in Vault.** Works today without new code, but needs Vault, which
   is what this ADR is meant to avoid.
3. **Part B at the authority, per machine.** A secret in the journal would
   lie at every instance and in every archive until compaction, and needs a
   write path from machines into the journal; a clone inside the bound
   network could overwrite it.
4. **The authority encrypts and decrypts the secret** (wrap and unwrap). The
   authority would see every secret.
5. **Plain Tang: one key per instance.** Any machine that passes its own
   checks could open any other machine's part A at the same instance.
6. **TPM-sealed credentials** (`systemd-creds` with a vTPM). Binds a secret
   to one VM's TPM state, not to a place; a copy of the VM with its vTPM
   state opens it. Good for a single VM, out of scope here.

## Decision outcome

Chosen option 1.

### Keys at the authority

- Each instance that takes part holds an **exchange key**: 32 random bytes
  in a file (`exchange_key_file`), mode 0600. It is kept like the signing
  key: optionally encrypted with the same passphrase, so that one unseal
  opens both, and never in a backup. Part A lies in the machines' backups;
  a backup of the exchange key next to it would open every secret pinned to
  that instance without any check.
- Losing the exchange key, or replacing it, takes the instance out of every
  secret pinned to it. Daemons re-split such secrets over the remaining
  instances (below).
- For an identity `id` in trust domain `td` the instance derives the scalar

  ```text
  s = OS2IP(HKDF-SHA256(ikm = exchange key, salt = "ergosum/v1/exchange",
                        info = td || 0x00 || id, L = 48)) mod n
  ```

  with `n` the order of P-256 (48 bytes make the bias negligible; `s = 0`
  is rejected). `S = s·G` is the **release key** of `id` at this instance.
- The derivation must not be linear in the identity. With `s = x + H(id)`,
  a machine holding another machine's part A could compute that machine's
  value from its own: `s₁·C = s₂·C − (H(id₂) − H(id₁))·C`. HKDF has no such
  relation.

Points are encoded as compressed SEC1 (33 bytes) in unpadded base64url.

### The exchange

To pin a secret to an instance, the daemon takes the release key `S` of its
identity there, picks a random `c`, computes `C = c·G` and `K = c·S`, and
forgets `c`. Part A keeps `C`; `K` encrypts the instance's share.

To open the share again, the daemon picks a random `e` and sends the
blinded point `X = C + e·G`. The instance answers `Y = s·X`, and the daemon
computes `K = Y − e·S`. `X` is uniformly random to the instance; it learns
nothing about `C` or `K`. Both sides reject a point that is not on the
curve or is the point at infinity.

A machine with another machine's part A passes its own checks and receives
`s'·X` for its own scalar `s'`, which yields `s'·C`, unrelated to `s·C`.

### Exchange endpoint

`POST /v1/exchange` on the token listener, body: envelope (ADR 0001),
context `ergosum/v1/exchange-request`:

```json
{
  "v": 1,
  "type": "exchange_request",
  "identity": "host1.example.com",
  "request_id": "...",
  "timestamp": "...",
  "addresses": ["192.0.2.10"],
  "key": "<base64 DER SubjectPublicKeyInfo>",
  "to": "SHA256:<fingerprint of the authority instance>",
  "points": ["<X>", "..."]
}
```

The members other than `type` and `points` mean what they mean in a token
request. `points` holds 0 to 32 points; with none, the request only fetches
the release key. The instance validates the points with the envelope (step
1 of the authority procedure in ADR 0001) and then runs that procedure
unchanged: the same in-flight rule, the same rate limit shared with token
requests, the same replay set, the same callbacks and the same evidence.
Where the procedure would issue a token, the instance answers `200`:

```json
{
  "v": 1,
  "release_key": {"payload": "...", "signature": "..."},
  "points": ["<Y>", "..."],
  "server_time": "..."
}
```

`release_key` is an envelope signed with the instance key, context
`ergosum/v1/release-key`:

```json
{"v": 1, "type": "release_key", "trust_domain": "example.com",
 "identity": "host1.example.com", "authority": "<kid>", "key": "<S>"}
```

- Errors are those of ADR 0001. `not_responsible` keeps an instance out of
  the identity's secrets, as it should: it cannot run every check.
- An instance without an exchange key answers 404 `no_exchange`; an
  instance of an earlier version answers a plain 404. The daemon pins
  neither.
- A successful exchange writes nothing to the journal: there is no token
  and therefore no `issued` observation. The audit log records the
  identity, the request ID, the number of points and the outcome. Failed
  exchanges produce the same observations as failed token requests
  (`key_duplicate`, `wrong_location`, `replay`, `misdirected`), with the
  format unchanged.

### Part A

A JSON file, written by the CLI:

```json
{
  "v": 1,
  "type": "sealed_secret",
  "name": "restic",
  "trust_domain": "example.com",
  "identity": "host1.example.com",
  "threshold": 1,
  "pins": [
    {"authority": "SHA256:<instance key fingerprint>",
     "release_key": {"payload": "...", "signature": "..."},
     "client_point": "<C>",
     "share": "<nonce || AES-256-GCM ciphertext>"}
  ],
  "ciphertext": "<nonce || AES-256-GCM ciphertext>",
  "recovery": "<optional ASCII-armored age file>"
}
```

- A random 32-byte **master** `m` encrypts the secret: AES-256-GCM with the
  key `HKDF-SHA256(ikm = m, salt = "ergosum/v1/secret", info = td || 0x00
  || id || 0x00 || name, L = 32)`, a random 96-bit nonce and the associated
  data `ergosum/v1/sealed-secret`.
- `m` is split with Shamir's scheme over GF(2⁸) (AES polynomial), byte by
  byte, with a random polynomial of degree k − 1; pin i (1-based, in the
  order of `pins`) holds the value at x = i. With k = 1 every share is `m`.
- Each share is encrypted with AES-256-GCM under `HKDF-SHA256(ikm =
  x-coordinate of K, salt = "ergosum/v1/share", info = authority || 0x00 ||
  td || 0x00 || id || 0x00 || name, L = 32)`, a random nonce, and `C` as
  associated data.
- `recovery`, if present, is the secret encrypted with age to the recipients
  given at creation (X25519 or `ssh-ed25519`). It is the way back when no
  instance can be reached: an administrator opens it with the stock `age`
  tool and the private key, without ergosum.
- Limits: at most 16 pins, a threshold from 1 to the number of pins, a
  secret of at most 64 KiB, part A of at most 1 MiB.

### Commands

The commands are part of `ergosumd`, which every machine has:

- `ergosumd secret create NAME -threshold K [-recovery RECIPIENT]... [-file
  PATH]` reads the secret from stdin until EOF and removes one trailing LF
  or CRLF (`-raw` keeps it). The daemon sends an exchange request without
  points to every instance of its authority list and pins each one that
  answers with a valid release key for its identity. With fewer than K pins
  it fails and names the instances that did not answer and why. The CLI
  writes part A to PATH, default `/etc/ergosum/secrets/NAME`, mode 0600, and
  never overwrites an existing file. NAME consists of lower-case letters,
  digits and hyphens, at most 63 characters.
- `ergosumd secret get NAME` (or `-file PATH`) writes the secret to stdout:
  the bytes as stored, no trailing newline, nothing else. Exit code 0. On
  any failure, stdout stays empty, a message goes to stderr, and the exit
  code is 1.
- `ergosumd secret info NAME` (or `-file PATH`) shows name, identity,
  threshold and pins, never the secret.

### Who may open a secret

- The CLI reads part A with the caller's rights and passes its content over
  the daemon's local socket. The daemon answers only for the part A it is
  given; its cache is keyed by the SHA-256 of the exact bytes. The file
  permissions of part A decide who may open a secret.
- The socket lies next to the token file (`/run/ergosum/secret.sock` by
  default), mode 0600, owned by the daemon's user; `secret_socket_group`
  opens it to one group (mode 0660). Every live exchange spends the
  identity's rate budget at the authorities, and a local user without
  access must not be able to keep the machine from its token.
- The daemon logs each request with the caller's UID from the socket's peer
  credentials.
- The protocol on the socket belongs to one binary and is not part of this
  ADR.

### Releases per round

- When `get` brings a part A the daemon does not hold, it asks the listed
  instances among the pins, in list order, until it has K answers, opens the
  secret and keeps it in memory with its part A.
- After each token round, the daemon refreshes every secret it holds: one
  exchange request to every listed pinned instance, carrying the points of
  all held secrets pinned there.
- `get` answers from memory while the daemon holds an unexpired token and
  no pin denied (403) the last refresh of that secret; otherwise it opens
  the secret anew. An outage of the authorities therefore does not stop a
  consumer while the token lasts; a revoked binding stops it at the next
  round.
- Memory only: after a restart of the daemon, the first `get` of each
  secret needs K reachable instances.

### Re-splitting

- When the daemon takes a new authority list (ADR 0001), it checks every
  secret it holds against it. A pinned instance that is no longer listed
  drops out, and a listed instance that is not pinned is tried with an
  exchange request without points. A listed instance that was unreachable is
  tried again once per hour; one that answered `not_responsible` or 404 is
  not tried again until the list changes.
- The authority list is not signed by administrators. The daemon therefore
  re-splits only if at least K of the secret's pinned instances serve the
  same list (serial and content) on `GET /v1/authorities`. Redirecting a
  secret to other instances then takes as many instances as opening it.
- Re-splitting keeps `m` and the ciphertext and makes new shares for the
  new set of pins, with new client points. If fewer than K instances can be
  pinned, the daemon keeps the old part A and does not lower the threshold.
- The daemon cannot write part A. It hands the new part A to the next
  `get`, which replaces the file atomically with the same owner and mode
  and says so on stderr. If the CLI cannot write the file, the re-split
  stays pending.

### Metrics

- Daemon, per secret it holds (label `name`):
  `machine_identity_secret_threshold`, `machine_identity_secret_pins`
  (pinned instances that answered the last refresh),
  `machine_identity_secret_reshare_pending`.
- Authority: `machine_identity_exchanges_total{result}`, with the results
  of `machine_identity_requests_total`.

A secret with fewer answering pins than its threshold needs an alert, not a
lower threshold.

### Versioning

- The exchange request and response, the release key and part A carry
  `"v": 1`; the path is `/v1/exchange`; every context contains `v1`. The
  rules of ADR 0001 apply.
- Daemons of earlier versions never call `/v1/exchange`; authorities of
  earlier versions answer it with 404. Nothing in ADR 0001 to 0003
  changes.

### Limits

- No rotation: a changed secret needs a new part A. Old copies of part A,
  for example in backups, open as long as their pins' exchange keys exist
  and the identity passes its checks.
- No revocation of a single secret, only of the binding. No audit of single
  reads: the audit log shows exchanges per round, not each `get`.
- Root on the machine reads part A and reaches the socket. The daemon holds
  open secrets in memory, and a snapshot with memory contains them.
- The authority must run on another machine than the consumers of its
  secrets.
- A clone inside the bound network passes all checks, as it does for
  tokens.
- Whoever holds the identity key and passes its checks can evaluate the
  identity's scalar on any point: the exchange is an oracle for that
  identity, just as the token is the identity's bearer credential.
- With k = 1, one instance's exchange key plus a copy of part A opens the
  secret without any check. A compromised instance can already issue tokens
  for every identity; k = 2 raises the bar for the exchange only.

## Consequences

**Good**

- Secrets without Vault: part A may lie in backups and repositories, and a
  copy outside the machine's place opens nothing.
- The authority stays without state per machine; the journal stays free of
  secrets and unchanged.
- New instances join without a change on the machines.
- `ergosumd secret get` works as a password command for any tool that has
  one.
- The way back needs only `age` and an administrator's key.

**Bad**

- Every pinned instance runs one more set of callbacks per round, and the
  exchange shares the rate budget with token requests.
- The first `get` after a daemon restart needs the authorities; a reboot of
  a machine during an outage of too many instances leaves its consumers
  without their secret until the instances return or an administrator uses
  the way back.
- The exchange key is new key material per instance, with its own backup
  rule.
- A re-split rewrites part A from inside a `get`.
- The recovery recipients add the age format to `ergosumd`.
