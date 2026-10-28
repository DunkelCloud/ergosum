# Operations

All addresses below are documentation examples (RFC 5737, RFC 3849).

## Users and directories

| Path | Owner, mode | Content |
| --- | --- | --- |
| `/etc/ergosum/` | root, 0755 | `ergosumd.yaml`, `serve.yaml`, `signing.key` (0640, group `ergosum`) |
| `/var/lib/ergosum/` | `ergosum`, 0700 | daemon: `identity.key` (0600); authority: `journal.db`, `control.sock`, optionally `archive/` |
| `/run/ergosum/token` | `ergosum`:`ergosum-token`, 0640 | identity token, read by Vault Agent |

Create the user and groups with `deploy/sysusers.d/ergosum.conf`
(systemd), or on Alpine:

```sh
addgroup -S ergosum-token
adduser -S -D -H -h /var/lib/ergosum -s /sbin/nologin ergosum
addgroup ergosum ergosum-token
addgroup vault ergosum-token   # the user Vault Agent runs as
```

Service definitions: `deploy/systemd/` and `deploy/openrc/` (Alpine,
`supervise-daemon`). Both binaries run in the foreground and log JSON lines
to stdout.

Exclude `/var/lib/ergosum/` and `/var/lib/tailscale/` from backups on
machines: a restored machine is enrolled again with a new key, and a backup
must carry neither the identity key nor the overlay node key (see
[Backups](#backups)).

## Daemon

1. Install `ergosumd`, write `/etc/ergosum/ergosumd.yaml`
   (`examples/ergosumd.yaml`).
2. `sudo -u ergosum ergosumd fingerprint` creates the key on first use and
   prints the fingerprint for the binding. Run it as the service user: a key
   created by root belongs to root, and the service cannot read it.
3. Allow TCP 7433 (or the configured callback port) from the authorities'
   source addresses only. The listener is open only while a request is in
   flight.
4. Start the service. The daemon requests a token, writes it to
   `/run/ergosum/token`, and renews it from half its lifetime on.

`addresses` may stay empty: the daemon reports its global unicast addresses
outside the overlay, those of physical-looking interfaces first, at most 16.
A host with many bridge or tunnel addresses logs a warning when it has to
leave some out; name the addresses inside the bound networks in `addresses`
then.

Metrics (node_exporter textfile collector, `metrics_file`):

| Metric | Meaning |
| --- | --- |
| `machine_identity_token_expiry_timestamp_seconds` | expiry of the current token |
| `machine_identity_last_success_timestamp_seconds` | last successful request |
| `machine_identity_last_error_timestamp_seconds` | last failed request |
| `machine_identity_clock_skew_seconds` | authority clock minus local clock |
| `machine_identity_callbacks_total{status}` | callbacks answered; any `no_open_request` means the key is used elsewhere |

Short token lifetimes need synchronized clocks.

## Authority

### Signing key

```sh
ergosum keygen -out /etc/ergosum/signing.key            # plain key file
ergosum keygen -out /etc/ergosum/signing.key -encrypt   # passphrase-encrypted
```

`keygen` prints the key ID, the fingerprint for the daemons' `authorities`
list, and the PEM public key for the token verifier. It writes the file with
mode 0600 for the user who runs it; hand it to the service user before the
first start:

```sh
chgrp ergosum /etc/ergosum/signing.key && chmod 0640 /etc/ergosum/signing.key
```

With an encrypted key the instance starts **sealed** after every start: it
serves only metrics, health and its public key, and issues nothing until an
operator runs, on the same host,

```sh
ergosum unseal                       # reads the passphrase from the terminal or stdin
```

The control socket (`/var/lib/ergosum/control.sock`, mode 0600) is the only
way in; it is not reachable over the network. A sealed instance does not
restart into service on its own; another instance keeps issuing meanwhile.
`machine_identity_authority_sealed` is 1 while sealed — alert on it.

### Listener

`listen` is required and names the address the API binds to, normally the
instance's overlay address (`100.64.0.10:7432` in `examples/serve.yaml`).
An address that binds all interfaces (`:7432`, `0.0.0.0:7432`,
`[::]:7432`) is refused unless `listen_all_interfaces: true` is set; on a
public host that would expose the API to the internet.

### Modes of operation

The authority runs as a native binary (`ergosum serve`) or as the OCI image,
on a host of its own or on a shared host.

- **Shared host.** Whoever controls the host controls the instance and can
  issue tokens for any identity. The host inherits the highest protection
  class of the authority. Ports and callback source addresses are
  configurable so that the authority fits next to other services, and so
  that the host's overlay network or exit node cannot carry underlay
  callbacks: set `callbacks.ip.source` (and `interface`, which needs
  `CAP_NET_RAW`) to the public address and interface.
- **OCI image.** Non-root (65532), works with a read-only root filesystem:

  ```sh
  docker run -d --name ergosum --read-only \
    -v ergosum-state:/var/lib/ergosum \
    -v /etc/ergosum:/etc/ergosum:ro \
    --network host \
    ghcr.io/example/ergosum:latest
  docker exec -it ergosum ergosum unseal
  ```

  Host networking keeps source addresses and attached networks as on the
  host; with bridged networking `net` checks see only the bridge.

### Callback rules

- `tailnet` callbacks must reach an overlay address (`callbacks.tailnet.prefixes`).
- `ip` and `net` callbacks must neither reach nor leave from an overlay
  address.
- `net` checks run only for prefixes inside `callbacks.networks`, the
  networks attached directly to this instance; other instances answer
  "not responsible" and the daemon moves on.

### Metrics and audit

`/metrics` on the ops listener (default `127.0.0.1:7434`):

| Metric | Meaning |
| --- | --- |
| `machine_identity_requests_total{result}` | `issued`, `key_duplicate`, `wrong_location`, `replay`, `foreign_key`, `unknown_identity` |
| `machine_identity_authority_sealed` | 1 while sealed |
| `machine_identity_binding_events_total{outcome}` | write API: `accepted`, `rejected` |
| `machine_identity_journal_outbox_events{peer}` | events a peer has not acknowledged |
| `machine_identity_journal_outbox_oldest_age_seconds{peer}` | age of the oldest of them; 0 if none |
| `machine_identity_journal_rejected_total{peer}` | events from a peer that ingest rejected |
| `machine_identity_journal_coverage{origin}` | sequence number up to which every event of an origin is here |
| `machine_identity_journal_compaction_frontier{origin}` | sequence number up to which events of an origin may be deleted |
| `machine_identity_journal_checkpoint_age_seconds` | age of the latest own checkpoint; -1 before the first |
| `machine_identity_journal_compacted_events_total` | events deleted by compaction |

`key_duplicate` is proof that a machine key exists twice and deserves a
critical alert. `replay` means that someone with the machine key reused a
request ID the machine had sent, typically a copy from a disk image; treat
it like `key_duplicate`. Both are logged at level `error` with an `alert`
field. `wrong_location` is a warning.

Audit entries are JSON log lines with `"log_type":"audit"` on stdout — one
per token request (result, identity, request ID, presented key, per-check
outcome, token ID) and per binding write — ready for any log pipeline.
Requests that do not verify against a bound key (`foreign_key`,
`unknown_identity`, and timestamps outside the window) and rejected binding
writes can come from anyone: they are never journaled, and their log lines
are limited to 60 per minute in total. The metrics count all of them.

## Replication

Every instance holds the whole journal and replicates it to the others over
mutual TLS with the instance keys (ADR 0003). There is no leader: a binding
written at any instance reaches all others, and an instance that was down
receives what it missed from its peers' outboxes.

```yaml
replication:
  listen: "100.64.0.10:7435"       # overlay address; required with peers that have a url
  peers:                           # every other instance
    - name: authority-b            # its "instance"
      url: https://100.64.0.11:7435
      key: |                       # its public key, from "ergosum keygen"
        -----BEGIN PUBLIC KEY-----
        ...
```

Allow TCP 7435 between the instances only. A peer without `url` is known
(its events are accepted when another instance forwards them) but receives
no pushes from here, and compaction does not wait for it. Name every
instance on every instance: its key verifies its observations and
checkpoints wherever they arrive. An instance keeps its key for the life of
its name; a new key is a new instance name.

`GET /v1/journal/state` on the ops listener reports the state hash, the
coverage and compaction frontier per origin, and the outbox of every peer.
Instances with the same binding events have the same state hash.

An event that fails verification at ingest is rejected with an audit line
at level `error` (`"alert"`), `machine_identity_journal_rejected_total`
counts it, and replication from that peer stops there until the cause is
fixed: usually a registry that differs between the instances, otherwise a
forged event. The sender keeps the event and retries.

### Adding an instance

1. `ergosum keygen` on the new instance; write its configuration with all
   other instances as peers.
2. Add the new instance to `replication.peers` of every existing instance,
   without `url` until it is running, and restart them.
3. Start the new instance (and unseal it), then pull the journal before
   anything is written to it:

   ```sh
   ergosum journal sync -from authority-a -from authority-b
   ```

   Several peers give the union of what they hold, so one peer cannot
   withhold a binding event.
4. Add the `url` on the other instances, so that they push to it, and
   restart them.

A rebuilt instance keeps its name and key and follows the same steps; it
must sync before it accepts writes, or its new events would reuse sequence
numbers its peers know.

### Removing an instance

Remove it from `replication.peers` on every other instance. Compaction
waits for every peer with a `url`; a peer that is gone for good keeps the
journal growing until it is removed.

## Checkpoints, compaction and export

Every instance writes a checkpoint, signed with its key, of the projection
(every winning binding event with its administrators' signatures) and its
coverage: daily if the journal changed, and on `ergosum journal checkpoint`.
An event is deleted only when the latest own checkpoint that every peer has
acknowledged covers it, every peer has acknowledged the event itself, and
the retention of its kind has passed; a trigger in the database refuses to
delete anything above that frontier.

```yaml
compaction:
  checkpoint_interval: 24h
  interval: 1h              # how often a checkpoint is considered and compaction runs
  retention:
    observations: 2160h     # 90 days; 0 keeps them
    key_duplicate: 0s       # evidence of a copied key: kept
    bindings: 0s            # binding history: kept; the winners live on in the checkpoint
  archive: /var/lib/ergosum/archive   # optional
```

With an archive, compaction first writes the events not yet archived to a
new file there (JSON lines), and deletes only archived events. Commands on
the local instance:

```sh
ergosum journal state                  # state hash, coverage, frontier, outboxes
ergosum journal checkpoint
ergosum journal compact                # archive, raise the frontier, delete
ergosum journal export -out FILE       # the whole journal as JSON lines
ergosum journal export -archive        # what is not yet archived, into the archive
```

An export needs no trust in where it is kept: observations and checkpoints
are signed by their instance, binding events by administrators, and gaps in
the sequence numbers of an origin show. Keep a current export with the
recovery material of the deployment.

## Trust root: administrator keys and the registry

The registry names the administrator keys and, per event kind, how many of
them must sign. Whoever controls enough administrator keys, or the registry
of an instance, can bind any identity to any key. Treat both as the highest
protection class:

- Keep administrator keys on security keys (`sk-ssh-ed25519`,
  `sk-ecdsa-sha2-nistp256`), which also prove presence for each signature,
  or at least passphrase-protected and never on an authority host.
- Set `approvals` to 2 or more for `binding.set` where two administrators
  are available.
- The registry is static configuration. Change it on every instance through
  the same reviewed deployment; until all instances run the new registry,
  instances with the old one reject events signed only by new keys, and
  replication from the others stops at such an event (see Replication).
- Before an administrator key leaves the registry, have the remaining
  administrators approve again, at the next epoch, every binding that only
  that key approved, and let compaction remove the older events (retention
  for `bindings`). Ingest verifies history against the current registry; an
  event approved only with a removed key stops a sync.

## Writing a binding

`ergosum bind`, `ergosum revoke` and `ergosum sign` read the current epoch
from an authority, show the canonical text, sign it with `ssh-keygen -Y sign`
and merge the signatures of several administrators. A configuration saves
the flags:

```yaml
# ~/.config/ergosum/admin.yaml (or $ERGOSUM_ADMIN_CONFIG)
trust_domain: example.com
authorities:                     # tried in order
  - url: https://100.64.0.10:7432
    key: SHA256:...              # instance fingerprint, from "ergosum keygen"
```

```sh
# Administrator 1: build the event at the next epoch and sign it.
ergosum bind -identity host1.example.com -key SHA256:<from ergosumd fingerprint>   -check tailnet:host1.tailnet.example.com -check ip:192.0.2.10   -sign-key ~/.ssh/id_ed25519_sk -out host1.json
# Administrator 2, on another machine: check the text, sign, submit.
ergosum sign -sign-key ~/.ssh/id_ed25519 -submit host1.json
# Copies signed separately can be merged: ergosum sign -submit a.json b.json
ergosum revoke -identity host1.example.com -sign-key ~/.ssh/id_ed25519 -out revoke.json
```

`-sign-key` takes a private key file, a security key handle, or a public key
whose private key is in `ssh-agent`. The tool asks before it signs (`-yes`
skips the question) and checks every signature before it writes the file.
Without the tool, sign the canonical text (ADR 0003) directly:

```sh
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n ergosum-binding event.txt   # each admin
```

and post the JSON form with all signatures to `POST /v1/bindings` on any
instance. Admin keys are ed25519, ECDSA, RSA with at least 2048 bits, or
security keys; `ssh-dss` keys and certificates are refused.

## Enrollment and decommissioning

Enrollment of a machine:

1. Install `ergosumd` and its configuration; `sudo -u ergosum ergosumd
   fingerprint` creates the key and prints the fingerprint.
2. Administrators bind the identity to that fingerprint with the checks of
   its place (`ergosum bind`, `ergosum sign -submit`). The machine needs no
   bootstrap secret.
3. Start `ergosumd`; check that `/run/ergosum/token` appears and that the
   authority's audit log shows `issued` with every check.
4. Store the machine's backup settings in Vault and, while the role names
   its identities, add the identity there (see [Vault](#vault)).

After a restore or migration the machine gets a new key: delete the
daemon's state directory, create a new key and bind it at the next epoch.

Decommissioning:

1. `ergosum revoke` with the approvals the registry demands. Every instance
   stops issuing as soon as the revocation reaches it; a token already
   issued stays valid until it expires.
2. Wait until every instance has the revocation: the same state hash
   everywhere, and `GET /v1/bindings/<identity>` answers `binding.revoked`.
3. Revoke the Vault tokens of the machine's entity
   (`vault token revoke` by accessor, or disable the entity), and remove
   the identity from the role if the role names its identities.
4. Stop `ergosumd` and delete its state directory, so that no copy of the
   key remains on the disk.
5. Only now release the machine's addresses and overlay node. A released
   public address can be handed to someone else; while a binding still
   names it, that machine together with a stolen backup would pass the
   checks.
6. Remove the machine from monitoring and backups.

## Alerts

`deploy/prometheus/ergosum-alerts.yml` holds a proposal of alerting rules
for these metrics: proven key duplicates and replays, sealed instances,
rejected journal events, stuck outboxes, diverging coverage and stale
checkpoints.

## Vault

### Setup

`deploy/vault/machine-auth.sh` configures Vault (or OpenBao, with
`VAULT=bao`) and owns three objects:

| Object | Content |
| --- | --- |
| auth mount `machine` | JWT auth method; `jwt_validation_pubkeys` holds the public key of every authority instance, `bound_issuer` the shared `issuer` |
| role `host` | `bound_audiences` `vault`, `user_claim` `sub`, `bound_claims` on `sub` with the named identities (`-identity`, once per machine) or every identity of the trust domain (`-all-identities`), the `host` claim mapped into the alias metadata, Vault token TTL and max TTL 1 h, policy `host-secrets` |
| policy `host-secrets` | read on `secret/data/host/<host>/*`, `<host>` taken from the alias metadata of the login |

It creates or updates these objects and nothing else. An auth mount or a
policy of the same name that it did not create stops it. `plan` shows the
difference to what is there; `apply` shows it, asks, and writes only what
differs:

```sh
export VAULT_ADDR=https://vault.example.com:8200 VAULT_TOKEN=...
deploy/vault/machine-auth.sh plan -issuer https://ergosum.example.com \
  -trust-domain example.com -key authority-a.pem -key authority-b.pem \
  -identity host1.example.com -identity host2.example.com
deploy/vault/machine-auth.sh apply ...        # the same options
```

The public keys are the PEM blocks printed by `ergosum keygen`, or
`GET /v1/keys.pem` on each instance's ops listener. Every run states the
whole set: a key or identity left out is removed.

Vault accepts an identity token until its `exp` plus 60 s of clock skew; the
role sets `expiration_leeway` to -1 so that nothing is added on top. The
Vault token lives for an hour and cannot be renewed beyond that; then Vault
Agent logs in again with the identity token that is in the file at that
time.

The way back:

```sh
deploy/vault/machine-auth.sh rollback
```

It disables the mount, which revokes every Vault token issued through it,
and deletes the policy. It deletes neither the identity entities that logins
created nor the secrets below `secret/host/`.

### Secrets

Each machine has its own tree in the KV version 2 mount `secret` (`-kv`),
below `host/<identity>/` (`-prefix`), with one subpath per application. For
backups:

| Path | Keys |
| --- | --- |
| `secret/host/<identity>/backup/config` | `repository`, the restic repository, e.g. `s3:https://s3.example.com/backup/host1` |
| `secret/host/<identity>/backup/credentials` | `restic_password`, `access_key_id`, `secret_access_key` |

A machine reads everything below `secret/host/<identity>/`. Keep
credentials it must not hold, such as those to restore or to prune its
backups, outside that tree.

Secrets that several machines share, such as the credentials of a service
they all call, belong in one place outside the machine trees, for example
`secret/app/<application>/`, rather than in a copy per machine. Grant them
through a Vault identity group: a policy that reads the shared path, and
the machines' entities as members. A machine's token carries the group's
policies in addition to `host-secrets`. An entity appears with the first
login; to add a machine to a group before that, create its entity and an
alias named after its SPIFFE ID on the `machine` mount, and the first login
uses it.

The example template reads from `secret/data/host/<identity>/backup/`.
With another mount or prefix (`-kv`, `-prefix`), change the paths in the
template to match; the policy grants nothing else.

### Vault Agent

`examples/vault-agent/agent.hcl` logs in with auto-auth method `jwt`,
`path=/run/ergosum/token` and `remove_jwt_after_reading=false`: the daemon
replaces the file, and the agent reads it again for every login. It renders
`examples/vault-agent/backup.env.ctmpl` to `/run/vault-agent/backup.env`
(mode 0600, in memory only). The template takes the identity from the Vault
token, so it is the same on every machine. Service definitions:
`deploy/systemd/vault-agent.service` and `deploy/openrc/vault-agent`; the
agent's user must be a member of `ergosum-token`.

A backup job then runs

```sh
. /run/vault-agent/backup.env && restic backup ...
```

### Backups

Leave the daemon's state and the overlay node key out of machine backups:

```sh
restic backup --one-file-system --exclude /var/lib/ergosum --exclude /var/lib/tailscale /
```

`/run` is a tmpfs, so the identity token and the rendered settings are not
part of a backup with `--one-file-system`.

### Changing an authority's key

An instance keeps its key for the life of its name (ADR 0003): the key signs
its tokens, journal events and TLS, and peers and daemons pin it. A new key
is a new instance:

1. Create the new instance with `ergosum keygen` and a new `instance` name,
   and bring it into replication (see [Adding an instance](#adding-an-instance)).
2. Add its public key to Vault next to the old one: `machine-auth.sh apply`
   with both `-key` options.
3. Put the new instance into the daemons' `authorities` and restart them;
   their tokens now come from the new instance.
4. Remove the old instance from the daemons' `authorities`, from the other
   instances (see [Removing an instance](#removing-an-instance)) and from
   Vault with `machine-auth.sh apply` without its `-key`. Vault refuses its
   tokens from then on; Vault tokens obtained with them run out within the
   token TTL.

Step 2 comes before step 3: a token from a key Vault does not know yet
fails at login.
