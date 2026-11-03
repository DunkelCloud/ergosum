# Operations

All addresses below are documentation examples (RFC 5737, RFC 3849).

## Users and directories

| Path | Owner, mode | Content |
| --- | --- | --- |
| `/etc/ergosum/` | root, 0755 | `ergosumd.yaml`, `serve.yaml`, `signing.key` (0640, group `ergosum-authority`) |
| `/var/lib/ergosum/` | `ergosum`, 0700 | daemon: `identity.key` (0600) |
| `/var/lib/ergosum-authority/` | `ergosum-authority`, 0700 | authority: `journal.db`, `control.sock`, optionally `archive/` |
| `/run/ergosum/token` | `ergosum`:`ergosum-token`, 0640 | identity token, read by Vault Agent |

The daemon runs as `ergosum`, the authority as `ergosum-authority`: on a
host with both, a daemon that is taken over reaches neither the signing
key nor the journal. On a new machine `deploy/install.sh` creates the
daemon's user and group (see [Daemon](#daemon)). By hand: with
`deploy/sysusers.d/ergosum.conf` and, for an authority,
`ergosum-authority.conf` (systemd), or on Alpine:

```sh
addgroup -S ergosum-token
addgroup -S ergosum
adduser -S -D -H -h /var/lib/ergosum -s /sbin/nologin -G ergosum ergosum
addgroup ergosum ergosum-token
addgroup vault ergosum-token   # the user Vault Agent runs as
addgroup -S ergosum-authority   # authorities only
adduser -S -D -H -h /var/lib/ergosum-authority -s /sbin/nologin -G ergosum-authority ergosum-authority
```

Upgrading an authority that ran as `ergosum`: stop it, move
`/var/lib/ergosum/journal.db*` (and the archive) to
`/var/lib/ergosum-authority/`, `chown -R ergosum-authority:` that directory,
give `signing.key` to the group `ergosum-authority`, and adjust `journal`,
`control_socket` and `archive` in `serve.yaml` if they name the old place.

Service definitions: `deploy/systemd/` and `deploy/openrc/` (Alpine,
`supervise-daemon`), for the daemon on a Mac `deploy/launchd/`. Both
binaries run in the foreground and log JSON lines to stdout.

On a Mac the daemon follows macOS's layout: `/usr/bin` belongs to the
system, system accounts begin with an underscore, and launchd creates no
directories for a job, so the token lives on disk next to the state:

| Path | Owner, mode | Content |
| --- | --- | --- |
| `/usr/local/bin/ergosumd` | root, 0755 | the daemon |
| `/etc/ergosum/` | root, 0755 | `ergosumd.yaml`, `release-signers` |
| `/var/db/ergosum/` | `_ergosum`, 0755 | `token` (`_ergosum`:`ergosum-token`, 0640) |
| `/var/db/ergosum/state/` | `_ergosum`, 0700 | `identity.key` (0600) |
| `/var/log/ergosum/` | `_ergosum`, 0755 | `ergosumd.log`, the daemon's output |
| `/Library/LaunchDaemons/io.github.dunkelcloud.ergosumd.plist` | root:wheel, 0644 | the launchd job |

These are the daemon's defaults on macOS. `_ergosum` is a system account
in the local directory service: an ID below 500 that no user and no group
has, a group `_ergosum` with the same ID, no password, the shell
`/usr/bin/false`, the home `/var/empty`, hidden. `deploy/install.sh`
creates it and the group `ergosum-token` with `dscl` (see
`ensure_users_darwin` there for doing it by hand). Vault Agent's user joins
the group with:

```sh
sudo dseditgroup -o edit -a USER -t user ergosum-token
```

launchd does not rotate `ergosumd.log`.

Whether `/var/lib/ergosum/` and `/var/lib/tailscale/` go into a machine's
backups is a trade-off between a working restore and what a stolen backup
carries (see [Backups](#backups)).

## Daemon

A new machine, as root:

```sh
curl -fsSLO https://github.com/DunkelCloud/ergosum/releases/latest/download/install.sh
sh install.sh --domain example.com --anchor 'SHA256:...@https://100.64.0.10:7432'
```

`--anchor` names one authority instance: its key fingerprint and its URLs,
separated by commas (see `authorities` below). The fingerprint is the one
`ergosum keygen` printed, `SHA256:` and 43 characters of base64; the
authority also logs it when it starts. The identity names the
machine in its binding, in its token and in Vault: a DNS name in lower
case, which need not resolve. `--domain example.com` makes it the host name
in that domain, such as `host1.example.com`, so the same line serves every
machine. Without `--domain` the identity is the machine's `hostname -f`,
which must then give a full name; `--identity` gives any other. A run that
refuses its options, a short `hostname -f` for instance, changes nothing.
The script
([Releases](releasing.md#installing-and-updating)) installs `ergosumd` from
the latest signed release and creates what is missing: the user `ergosum`
and the group `ergosum-token`, the state directory, the systemd unit or
OpenRC script, and `/etc/ergosum/ergosumd.yaml` with the identity and the
anchor. Before it writes the configuration, `ergosumd check` connects to
the anchor's URLs: one that presents another key than the one in
`--anchor` stops the setup, one that cannot be reached yet does not. Then
it starts the daemon and prints the binding request for the
administrators (see [Administration](#administration)). Once they have
recorded the binding, the daemon receives its token on its own: until then
it asks again at intervals of up to five minutes. Run the same line again, and it
changes nothing that is there and prints the request again.

Allow TCP 7433 (or the configured callback port) from the authorities'
source addresses only. The listener is open only while a request is in
flight.

By hand instead:

1. Install `ergosumd`, create the users (see
   [Users and directories](#users-and-directories)) and write
   `/etc/ergosum/ergosumd.yaml` (`examples/ergosumd.yaml`).
2. `sudo -u ergosum ergosumd request -out host1.txt` creates the key on
   first use and writes the binding request for the administrators;
   `ergosumd fingerprint` prints only the fingerprint. Run both as the
   service user: a key created by root belongs to root, and the service
   cannot read it. `ergosumd check` shows the key each authority URL
   presents and fails if it is not the configured one.
3. Start the service. The daemon requests a token, writes it to
   `/run/ergosum/token`, and renews it from half its lifetime on.

`addresses` may stay empty: the daemon reports its global unicast addresses
outside the overlay, those of physical-looking interfaces first, at most 16.
A host with many bridge or tunnel addresses logs a warning when it has to
leave some out; name the addresses inside the bound networks in `addresses`
then.

`authorities` needs one instance, the anchor: its key and its URLs. After
the first token the daemon takes the [authority list](#authority-list)
that the instance serves, keeps it as `authorities.json` in `state_dir`,
and from then on tries the listed instances in their order, the configured
ones last. An anchor that cannot run the machine's `net` checks, or its
`ip` checks on private addresses, answers "not responsible"; a daemon
without a list then takes the anchor's list at once and asks the
instances that can. It takes a newer list (higher
serial) from any listed instance, and any list from a configured instance
that the list in use does not name;
so a new anchor in the configuration replaces a list from an old trust
domain. Of an instance's URLs the daemon tries only those it can reach from
its own addresses: an overlay address needs an overlay address on the
machine, IPv4 needs IPv4, other IPv6 needs IPv6. Each connection attempt
gives up after 5 s. Prefer addresses to names, which make every renewal
depend on DNS.

Metrics (node_exporter textfile collector, `metrics_file`):

| Metric | Meaning |
| --- | --- |
| `machine_identity_token_expiry_timestamp_seconds` | expiry of the current token |
| `machine_identity_last_success_timestamp_seconds` | last successful request |
| `machine_identity_last_error_timestamp_seconds` | last failed request |
| `machine_identity_clock_skew_seconds` | authority clock minus local clock, estimated from request rounds of at most 10 s |
| `machine_identity_callbacks_total{status}` | callbacks answered: `confirmed`, `ended` (a late callback for a request this daemon gave up), `no_open_request` (the key is used elsewhere) |
| `machine_identity_key_change_pending` | 1 while a new key waits for its binding |
| `machine_identity_build_info{version,commit}` | 1; version and commit of the running binary |
| `machine_identity_authorities_serial` | serial of the authority list in use; 0 while the daemon knows only its configuration |
| `machine_identity_secret_threshold{name}` | threshold of each secret the daemon holds open (see *Secrets without Vault*) |
| `machine_identity_secret_pins{name}` | pinned instances of that secret that answered its last refresh |
| `machine_identity_secret_reshare_pending{name}` | 1 while a re-split part A waits for the next `get` to write it |

Short token lifetimes need synchronized clocks.

### Secrets without Vault

A machine can keep a secret on its disk only sealed, as *part A*, and open
it after it has passed the checks of its binding at a threshold of authority
instances ([ADR 0004](adr/0004-releasing-secrets-without-vault.md)). Part A
may lie in backups and repositories: a copy elsewhere fails the checks and
opens nothing. The instances need an exchange key (see *Exchange key*).

```sh
# as root on the machine; reads the secret from stdin
printf '%s\n' "$RESTIC_PASSWORD" | ergosumd secret create restic -threshold 2 \
  -recovery 'age1...' -recovery 'ssh-ed25519 AAAA... admin@example.com'
ergosumd secret info restic
RESTIC_PASSWORD_COMMAND='ergosumd secret get restic' restic snapshots
```

- `create` pins a share to every instance of the authority list that hands
  out a release key for the machine (at most 16), and fails with fewer than
  the threshold, naming the instances that did not answer and why. It writes
  part A to `/etc/ergosum/secrets/NAME` (or `-file`), mode 0600, and never
  overwrites one. It removes one trailing newline from stdin; `-raw` keeps it.
- With `-file`, part A lies at that path, a relative one taken from the
  working directory. `get` and `info` look for NAME only in
  `/etc/ergosum/secrets` and need the same `-file`; `create` names it as an
  absolute path, the form a password command needs.
- `get` writes the secret to stdout as stored, without a newline, and
  nothing else; on any failure stdout stays empty and the exit code is 1. It
  fits every tool with a password command (`restic --password-command`,
  `RESTIC_PASSWORD_COMMAND`, `BORG_PASSCOMMAND`).
- `info` shows name, identity, threshold, pins and whether a recovery copy
  exists; it needs no daemon.
- Who may read part A may open the secret: the CLI reads the file with the
  caller's rights and hands it to the daemon over its socket
  (`secret_socket`, mode 0600; `secret_socket_group` opens it to one group).
  The daemon logs every request with the caller's UID.
- The daemon holds an opened secret in memory and answers from there while
  it holds a valid token and no pin denied the last refresh. After each
  token round it refreshes every held secret at its pinned instances, one
  request per instance. A revoked binding stops the secret at the next
  round; an outage of the authorities does not, while the token lasts.
  After a restart of the daemon, the first `get` needs the threshold of
  pinned instances.
- When the authority list changes, the daemon re-splits held secrets: it
  drops instances no longer listed and pins listed ones that hand out a
  release key, but only if at least the threshold of pinned instances serve
  the same list, and never below the threshold. The next `get` replaces part
  A atomically with the same owner and mode and says so on stderr; if it
  cannot write the file, the re-split stays pending.
- The way back without any instance: `recovery` in part A is an age file to
  the `-recovery` recipients. Copy that member to a file and run
  `age -d -i KEY file` with the stock `age` tool; ergosum is not needed.
- Alert when `machine_identity_secret_pins` drops below
  `machine_identity_secret_threshold` (`ErgosumSecretPinsBelowThreshold` in
  `deploy/prometheus/ergosum-alerts.yml`), not by lowering the threshold.
- Limits: no rotation (a changed secret needs a new part A; old copies open
  as long as their pins' exchange keys exist), root on the machine reads
  part A and reaches the socket, and with a threshold of 1 one instance's
  exchange key plus a copy of part A opens the secret without any check.

### On a Mac

A Mac, Apple Silicon or Intel, is enrolled with the same line, run with
`sudo`:

```sh
curl -fsSLO https://github.com/DunkelCloud/ergosum/releases/latest/download/install.sh
sudo sh install.sh --domain example.com --anchor 'SHA256:...@https://100.64.0.10:7432'
```

The script installs `ergosumd` to `/usr/local/bin` and creates what is
missing of the account `_ergosum`, the group `ergosum-token`, the
directories (see [Users and directories](#users-and-directories)) and the
launchd job `io.github.dunkelcloud.ergosumd`, which it loads with
`launchctl bootstrap`. Updates restart the daemon with `launchctl kickstart
-k`; by hand:

```sh
sudo launchctl kickstart -k system/io.github.dunkelcloud.ergosumd   # restart
sudo launchctl print system/io.github.dunkelcloud.ergosumd          # state
sudo launchctl bootout system/io.github.dunkelcloud.ergosumd        # stop and unload
```

The identity is best given with `--domain`: a Mac without a host name of
its own answers `hostname -f` with its Bonjour name, such as
`hosts-macbook-pro.local`, which the script refuses.

The application firewall, if it is on, lets callbacks reach the daemon
only once it is allowed:

```sh
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/local/bin/ergosumd
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /usr/local/bin/ergosumd
```

For the binding request the daemon asks the Tailscale client for the
tailnet name: `tailscale` in `PATH`, otherwise the CLI inside the app
(`/Applications/Tailscale.app/Contents/MacOS/Tailscale`, App Store and
standalone versions) or Homebrew's. The request runs as `_ergosum`; where
it shows `# check tailnet NAME`, take the name from `tailscale status` as
the logged-in user. Addresses of tunnels (`utun`), bridges (Internet
Sharing, virtual machines) and Apple's peer-to-peer interfaces (`awdl`,
`llw`) count as virtual: their checks are proposed commented out, and
Ethernet and Wi-Fi (`en`) come first.

Vault Agent reads the token at `/var/db/ergosum/token` (`path` in
`agent.hcl`, see [Vault Agent](#vault-agent)).

Unlike `/run`, `/var/db/ergosum` survives a reboot, and the token with it.
Time Machine backs it up together with the key unless told otherwise (see
[Backups](#backups)):

```sh
sudo tmutil addexclusion -p /var/db/ergosum
```

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
chgrp ergosum-authority /etc/ergosum/signing.key && chmod 0640 /etc/ergosum/signing.key
```

The authority refuses to start with a key file that other users may read or
anyone but its owner may change (mode bits beyond 0640).

With an encrypted key the instance starts **sealed** after every start: it
serves only metrics, health and its public key, and issues nothing until an
operator runs, on the same host,

```sh
ergosum unseal                       # reads the passphrase from the terminal or stdin
```

To change a running instance to an encrypted key without a new key (Vault
and the authority lists stay as they are):

```sh
cd /etc/ergosum
ergosum keygen -from signing.key -encrypt -out signing.key.enc   # prints kid and fingerprint: unchanged
chgrp ergosum-authority signing.key.enc && chmod 0640 signing.key.enc
mv signing.key.enc signing.key        # then restart the instance and unseal it
```

`-from` refuses a key that is encrypted already, and checks the result by
decrypting it again. With `-exchange` it does the same for an exchange key,
with the signing key's passphrase. Copies of the plain key in earlier
backups or snapshots stay plain; where they matter, change the key instead.

The control socket (`/var/lib/ergosum-authority/control.sock`, mode 0600, run
`ergosum unseal` as `ergosum-authority` or root) is the only
way in; it is not reachable over the network. A sealed instance does not
restart into service on its own; another instance keeps issuing meanwhile.
`machine_identity_authority_sealed` is 1 while sealed — alert on it.

### Exchange key

An instance takes part in releasing secrets without Vault
([ADR 0004](adr/0004-releasing-secrets-without-vault.md)) only with an
exchange key: 32 random bytes from which it derives one release key per
identity.

```sh
ergosum keygen -exchange -out /etc/ergosum/exchange.key            # plain key file
ergosum keygen -exchange -out /etc/ergosum/exchange.key -encrypt   # with the signing key's passphrase
chgrp ergosum-authority /etc/ergosum/exchange.key && chmod 0640 /etc/ergosum/exchange.key
```

and in `serve.yaml`:

```yaml
exchange_key_file: /etc/ergosum/exchange.key
```

- The same mode rule as for the signing key applies. An encrypted exchange
  key opens at `ergosum unseal` with the signing key's passphrase; if it does
  not open, the instance stays sealed. An encrypted exchange key next to a
  plain signing key is refused.
- **Never back it up.** The machines' sealed secrets lie in their backups; a
  copy of the exchange key next to one opens it without any check.
- Losing or replacing it takes the instance out of every secret pinned to
  it; the daemons re-split those secrets over the remaining instances.
- Without an exchange key, `POST /v1/exchange` answers 404 `no_exchange`,
  and daemons pin no secret to the instance.

Exchange requests run the same procedure as token requests (checks, rate
limit shared with token requests, replay set, observations of failures), but
issue no token: a successful exchange writes nothing to the journal, only an
audit line with the number of points.

Upgrading from the first release: the setting `unseal_socket` is now
`control_socket`, and `instance` must consist of lowercase letters, digits,
`-` and `.` (at most 63 characters). A journal is pinned to its instance
name, so an instance whose name breaks that rule starts over under a new
name, with a sync from its peers.

### Listener

`listen` is required and names the address the API binds to, normally the
instance's overlay address (`100.64.0.10:7432` in `examples/serve.yaml`).
An address that binds all interfaces (`:7432`, `0.0.0.0:7432`,
`[::]:7432`) is refused unless `listen_all_interfaces: true` is set; on a
public host that would expose the API to the internet.

### Authority list

`authorities_file` (`examples/authorities.yaml`) names every instance of
the trust domain with the URLs daemons reach it on, in order of preference;
the instance serves it at `/v1/authorities` (ADR 0001). Keep the same file
on every instance, list each instance on every path a daemon may take
(overlay, underlay IPv4 and IPv6), and raise `serial` with each change:
daemons take a list only with a higher serial. An instance reads the file
again when it changes, without a restart or an unseal; a file that turns
invalid leaves the last good list in place and logs an error. An instance
does not start with a file that does not name it. `ergosum authorities`
shows what every instance serves and whether they agree.

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
    -v ergosum-state:/var/lib/ergosum-authority \
    -v /etc/ergosum:/etc/ergosum:ro \
    --network host \
    ghcr.io/example/ergosum@sha256:...
  docker exec -it ergosum ergosum unseal
  ```

  Name the image by digest, not by a tag such as `latest`: a tag can
  move, and the authority must run exactly the binary that was checked.

  Host networking keeps source addresses and attached networks as on the
  host; with bridged networking `net` checks and `ip` checks on private
  addresses see only the bridge. The signing key must be readable by 65532
  and by no other user:
  `chown 65532 /etc/ergosum/signing.key`, mode 0600.

### Callback rules

- `tailnet` callbacks must reach an overlay address (`callbacks.tailnet.prefixes`).
- `ip` and `net` callbacks must neither reach nor leave from an overlay
  address.
- `net` checks run only for prefixes inside `callbacks.networks`, and
  `ip` checks on private addresses (RFC 1918, IPv6 unique local) only for
  addresses inside them; other instances answer "not responsible" and the
  daemon moves on.
- An `ip` check on an address inside `callbacks.networks` leaves by that
  network's route, any other by `callbacks.ip`.

Each entry of `callbacks.networks` names a network and the `source`
address and `interface` its callbacks leave from, for `net` and `ip`
checks alike. The authority does not check how the network is reached, so
one instance can serve many networks or VLANs:

- **Attached:** the instance has an address in the network, on an
  interface of its own or on a VLAN subinterface of a trunk, one per VLAN,
  without routing between them. A callback reaches only that segment; this
  is the strongest form.
- **Routed:** the instance reaches the networks through a router of your
  own; list them, or one prefix that covers them, with the interface
  towards the router. A check then shows that the machine answers at its
  address as that router delivers it. That is weaker than an attached
  segment and holds only while no other path carries the prefix, such as a
  VPN with an overlapping network. Allow the callback port from `source`
  into those networks.

Machines with fixed private addresses are bound with `ip` checks and need
the same entries as machines in DHCP networks with `net` checks: list the
network on every instance that should check them.

### Metrics and audit

`/metrics` on the ops listener (default `127.0.0.1:7434`):

| Metric | Meaning |
| --- | --- |
| `machine_identity_requests_total{result}` | `issued`, `key_duplicate`, `wrong_location`, `replay`, `misdirected`, `rate_limited`, `foreign_key`, `unknown_identity` |
| `machine_identity_exchanges_total{result}` | exchange requests (ADR 0004), with the same results; `issued`: the points were evaluated |
| `machine_identity_authority_sealed` | 1 while sealed |
| `machine_identity_build_info{version,commit}` | 1; version and commit of the running binary |
| `machine_identity_binding_events_total{outcome}` | write API: `accepted`, `rejected` |
| `machine_identity_journal_outbox_events{peer}` | events a peer has not acknowledged |
| `machine_identity_journal_outbox_oldest_age_seconds{peer}` | age of the oldest of them; 0 if none |
| `machine_identity_journal_rejected_total{peer}` | events from a peer that ingest rejected |
| `machine_identity_journal_equivocations_total{origin}` | events skipped because their origin signed a contradicting event; take that instance out of service |
| `machine_identity_journal_skipped_total{origin}` | observations and checkpoints skipped over the quota of their origin, or too far above its coverage; check that instance |
| `machine_identity_journal_origin_bytes{origin}` | what the observations and checkpoints of another origin take here, against `origin_quota_mib` |
| `machine_identity_journal_coverage{origin}` | sequence number up to which every event of an origin is here |
| `machine_identity_journal_compaction_frontier{origin}` | sequence number up to which events of an origin may be deleted |
| `machine_identity_journal_checkpoint_age_seconds` | age of the latest own checkpoint; -1 before the first |
| `machine_identity_journal_compacted_events_total` | events deleted by compaction |

`key_duplicate` is proof that a machine key exists twice and deserves a
critical alert. `replay` means that someone with the machine key reused a
request ID the machine had sent, typically a copy from a disk image; treat
it like `key_duplicate`. `misdirected` means that a request signed by the
machine but addressed to another instance arrived here: that instance, or
whoever relayed the request, passed it on. All three are logged at level
`error` with an `alert` field. `wrong_location` is a warning.
`rate_limited` counts requests of an identity beyond 10 and then one per
minute, or while another of its requests is in flight; a daemon renewing
every quarter of an hour never gets there. Many of them come from a copy
of the machine key, usually together with `key_duplicate`.

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
  max_page_mib: 32                 # largest page sent and accepted; the same everywhere
  origin_quota_mib: 1024           # what another instance's observations may take here
```

Allow TCP 7435 between the instances only. A peer without `url` is known
(its events are accepted when another instance forwards them) but receives
no pushes from here, and compaction does not wait for it. Name every
instance on every instance: its key verifies the position of every event it
recorded, its observations and its checkpoints wherever they arrive. An
instance keeps its key for the life of its name; a new key is a new
instance name.

Pages are cut to `max_page_mib`, but a checkpoint travels whole and needs
about 1.6 KB per identity. A page that is too large is refused with `413`
and logged on the sender ("page larger than max_body"); raise the value on
every instance before a checkpoint reaches it (32 MiB hold about 20 000
identities).

`origin_quota_mib` bounds what the observations and checkpoints of each
other instance take in this journal; beyond it they are skipped, with the
alert `ErgosumJournalEventsSkipped`. An observation takes about 1.5 KB, and
an instance writes one per token request it answers: 100 machines renewing
every quarter of an hour at one instance make about 15 MB a day, 1.3 GB
over a retention of 90 days. Size the quota above that for the busiest
instance, with `machine_identity_journal_origin_bytes` as the measure.

`GET /v1/journal/state` on the ops listener reports the state hash, the
coverage and compaction frontier per origin, and the outbox of every peer.
Instances with the same binding events have the same state hash.

An event that fails verification at ingest is rejected with an audit line
at level `error` (`"alert"`), `machine_identity_journal_rejected_total`
counts it, and replication from that peer stops there until the cause is
fixed: usually a registry that differs between the instances, otherwise a
forged event. The sender keeps the event and retries. A failure that says
nothing about the event, such as a database error, is answered with `503`
and retried without an alarm; a lasting one shows as a stuck outbox.

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
numbers its peers know. Only a sync takes over the coverage of the
checkpoint a peer's journal starts with, its own sequence counter included;
pushes never do. Sync from peers you trust: a compromised peer could claim
a coverage that makes the instance skip other instances' observations.

### Removing an instance

Retire it on every other instance: keep its entry in `replication.peers`
with `retired: true` and without `url`.

```yaml
    - name: authority-old
      retired: true      # its events stay valid; it may not connect any more
      key: |
        -----BEGIN PUBLIC KEY-----
        ...
```

A retired instance's key still verifies the events it wrote, which the
others keep and forward, so that a sync between them, or a new instance
built from one of them, still takes its history. It can no longer connect
(its key is no longer accepted on the replication listener), gets no
pushes, and compaction does not wait for it. Do not delete the entry while
any instance still holds events of that origin: the others would refuse
those events in a sync. Checkpoints only cover origins with a configured
key, and the coverage of an origin that is not configured at all is left
out when a checkpoint is checked.

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
  archive: /var/lib/ergosum-authority/archive   # optional
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
- A binding event names its trust domain, but no journal: once signed, it
  is valid in every journal of that trust domain, and anyone who reaches
  the API listener can write it to an instance where the identity's current
  epoch is lower. When the journals of a trust domain start over, after a
  trial or a loss without an export, start them with new administrator
  keys. Otherwise every event signed before, such as an old key of a
  machine, a test identity or a revocation, can come back and win against
  the new bindings.

## Administration

Bindings are changed from an administrator's machine with `ergosum` (builds
for Linux, Windows and macOS). Every change is one text file that grows
from step to step and that the people involved pass on:

1. The machine's administrator writes the request on the machine:
   `sudo -u ergosum ergosumd request -out host1.txt`. It holds the
   identity, the key and the checks the machine proposes from where it
   stands: its tailnet name, fixed addresses as `ip` checks, public and
   private alike, and the networks of private addresses from DHCP as `net`
   checks (see [Choosing checks](#choosing-checks)). A public address from
   DHCP or SLAAC, IPv6 addresses and virtual interfaces are proposed
   commented out.
2. An ergosum administrator checks the proposed checks, edits the file if
   needed and runs `ergosum bind host1.txt`. The tool adds kind, trust
   domain and the next epoch (read from an authority), shows the text to
   sign and how it differs from the current binding, signs with the
   administrator's key and appends the signature.
3. If the registry demands more approvals, the next administrator runs
   `ergosum bind host1.txt` on the same file. The tool records the event as
   soon as the signatures reach the threshold and notes where at the end of
   the file.

```text
# Binding request for host1.example.com, written by ergosumd request at ...
identity host1.example.com
key SHA256:...
# tailnet name (tailscale status)
check tailnet host1.tailnet.example.com
# eth0: fixed public address
check ip 192.0.2.10
# added by ergosum bind at ..., epoch from https://100.64.0.10:7432
kind binding.set
trust-domain example.com
epoch 4
# signed by alice (SHA256:...) at ...
-----BEGIN SSH SIGNATURE-----
...
-----END SSH SIGNATURE-----
```

The fields are the lines of the canonical text (ADR 0003) in any order;
`#` starts a comment, and line endings and encoding (UTF-8, or UTF-16 as
Windows PowerShell writes it) do not matter. Administrators see only this
format; the JSON form of an event exists only on the wire.

The tool refuses what would otherwise fail later or go unnoticed:

- If the text changed after a signature, it names the signature that no
  longer matches. Undo the change, or remove the signature and sign again.
- If the binding changed between making the file and recording it (another
  change took the epoch), the tool stops, and so does the authority (`409`):
  no change replaces another one unnoticed. Start with a new file.
- A key that the registry does not allow for the kind cannot sign, and a
  key signs only once.

### Choosing checks

`ip` is the check for a machine with a fixed address, in a public network
or a private one. `net` is for networks that hand out addresses by DHCP.
The difference shows with a copy of the machine's key: a copy anywhere
inside a bound `net` prefix passes that check, while an `ip` check reaches
only the bound address. While the original runs, it answers there that it
made no request, which proves the copy (`key_duplicate`); while it is off,
the copy fails unless it takes the original's address.

- `ergosumd request` proposes accordingly. On Linux it tells fixed
  addresses from leases by their lifetime in the kernel (`dynamic` in
  `ip addr` is a lease from DHCP or SLAAC). An older dhclient sets leases
  without a lifetime; they look fixed and are proposed as `ip` checks, so
  bind the network instead where the address can change.
- Addresses named in the daemon's `addresses` count as fixed. On macOS,
  which does not tell, public addresses are proposed as `ip` checks and
  private ones as `net` checks.
- An `ip` check on a private address runs only at an instance whose
  `callbacks.networks` holds the network, like a `net` check (see
  [Callback rules](#callback-rules)); the other instances answer "not
  responsible".

### Configuration

```yaml
# ~/.config/ergosum/admin.yaml, on Windows %AppData%\ergosum\admin.yaml
# (or $ERGOSUM_ADMIN_CONFIG)
trust_domain: example.com         # the authorities' trust domain
sign_key: ~/.ssh/id_ed25519.pub   # the administrator's key, see below
authorities:                      # one is enough if they serve a list
  - url: https://100.64.0.10:7432
    key: SHA256:...               # instance fingerprint, from "ergosum keygen"
# For "ergosum release sign" and "verify" (docs/releasing.md):
release_key: ~/.ssh/ergosum-release.pub
release_signers: ~/src/ergosum/release-signers
```

The tool first asks the configured authorities for their [authority
list](#authority-list) and adds the instances it names, each on the first of
its URLs reachable from this machine; the lists must agree. `ergosum
authorities` shows the lists, which instances are not configured here and
which configured ones the list lacks. The tool then reads from every
authority and insists that those that answer agree: on the trust domain (it must be the configured one), on the
approvals, and on the binding of the identity at hand. If they disagree,
`bind`, `revoke` and `show` stop and name both answers; that happens for a
moment while replication carries a change, and otherwise means that one
authority is wrong. `list` names the identities they disagree on. If only
one authority answers, the tool says that it could compare its answers with
none. A change goes to the first reachable authority; the tool then asks the
others for a few seconds whether they have it, and says which do not yet.
`-trust-domain`, `-authority` and `-authority-key` replace the configured
values.

`sign_key` is a public key (a file, or the key line itself) whose private
key the SSH agent holds: `ssh-agent` through `SSH_AUTH_SOCK`, on Windows
the OpenSSH agent service (`Get-Service ssh-agent`) or another agent whose
pipe `SSH_AUTH_SOCK` names. A public key in the SSH2 format, as PuTTYgen
exports it, works as well. If the agent does not hold the key, the tool
signs with `ssh-keygen -Y sign` and the private key file next to the public
one, which asks for the passphrase or the touch of a security key; a
private key file as `sign_key` is signed that way, too. `-sign-key`
overrides the configuration, `-yes` signs without asking.

The administrator's machine needs TCP 7432 to every authority: the read
side (`GET /v1/bindings`) and the write side share that listener. With one
reachable the tool still works, but cannot compare.

### Routine cases

| Case | Who | Commands |
| --- | --- | --- |
| Enrollment | the machine's administrator, then ergosum administrators | `ergosumd request` on the machine, `ergosum bind FILE` |
| Key change: routine, restore without state, after a duplicate-key alert | the machine's administrator, then ergosum administrators | `ergosumd request -new-key`, `ergosum bind FILE` |
| Other place or checks: new address, other network, an additional check | either | `ergosumd request` on the machine, or `ergosum show NAME -out FILE` and edit it; then `ergosum bind FILE` |
| Revocation, decommissioning | ergosum administrators | `ergosum revoke NAME` |
| Binding again under an old name | as enrollment | `ergosum bind` shows "revoked in epoch k" and takes k+1 |
| Renaming | enrollment for the new name, revocation for the old one | |
| Restore | | same place with the state directory: nothing; without it: key change; another place: other place |
| Looking up | anyone who reaches 7432 | `ergosum show NAME` (epoch, key, checks, who approved), `ergosum list` |

**Key change.** `ergosumd request -new-key` creates the next key next to the
current one (`identity.key.new`) and writes a request for it; asked again,
it names the same next key. The daemon keeps using the current key. Before
each request it asks every authority for its binding (`GET
/v1/bindings/<identity>`); once every authority that answers names the next
key, it switches and requests with the new one. One authority alone cannot
make it switch. The old key stays as `identity.key.old` until a token is
issued for the new one, then it is deleted. If every authority refuses the
new key (403), the daemon goes back to the old key, keeps the new one as
`identity.key.new` and asks again after ten minutes; an outage changes
nothing. No request is refused on the way, so no `foreign_key` appears.
`ergosum bind` shows the change as "key old -> new"; the old key is invalid
from the moment the binding is recorded. `machine_identity_key_change_pending`
is 1 while the next key waits. After a restore without the state directory
there is no old key: `ergosumd request` creates a new one.

**Revocation.** `ergosum revoke NAME` shows what it ends, writes
`NAME.revoke.txt` and continues as `ergosum bind`; another administrator
signs the same file if the registry demands it. Then follow
[Decommissioning](#decommissioning).

**Overlapping changes.** A file holds the epoch it was made for. If another
change is recorded first, the file is stale: the tool says so, and the
change starts again from a new request or `ergosum show`.

### Signing by hand

If the tool cannot sign, an administrator signs with `ssh-keygen` directly
and adds the signature to the file:

```sh
ergosum bind -text event.txt host1.txt   # completes host1.txt, writes the text to sign
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n ergosum-binding event.txt
cat event.txt.sig >> host1.txt          # PowerShell: Get-Content event.txt.sig | Add-Content host1.txt
ergosum bind host1.txt                   # checks the signature, records at the threshold
```

`-f` takes the private key or, with the key in the agent, its public key in
OpenSSH format. A public key in the SSH2 format (RFC 4716, as PuTTYgen
exports it) fails in `ssh-keygen` with a misleading "No such file or
directory"; `ssh-keygen -i -f key.pub > key-openssh.pub` converts it. Sign
`event.txt` as it is: opened and saved by an editor with CRLF line endings
it is a different text. `ergosum bind` recognizes a signature made over the
CRLF form, or in another namespace than `ergosum-binding`, and says so.

Without the tool at all, post the JSON form of the event (ADR 0003) with
all signatures to `POST /v1/bindings` on any instance. Admin keys are
ed25519, ECDSA, RSA with at least 2048 bits, or security keys; `ssh-dss`
keys and certificates are refused.

### Enrollment

1. On the machine, `install.sh --anchor ...` (see [Daemon](#daemon))
   installs and starts `ergosumd` and prints the request. Save it as
   `host1.txt` where the administrators run `ergosum`.
2. Administrators adjust the checks and record the binding with `ergosum
   bind`. The machine needs no bootstrap secret.
3. Check that `/run/ergosum/token` appears on the machine within a few
   minutes and that the authority's audit log shows `issued` with every
   check.
4. Store the machine's backup settings in Vault and, while the role names
   its identities, add the identity there (see [Vault](#vault)).

A machine restored at the same place together with its state directory
keeps its key and its binding and receives tokens again. Restored without
it, the machine needs a new key: delete what is left of the state
directory, write a request and bind it at the next epoch. A move to another
place always needs a binding with the new place's checks at the next epoch.

### Decommissioning

1. `ergosum revoke NAME` with the approvals the registry demands. Every
   instance stops issuing as soon as the revocation reaches it; a token
   already issued stays valid until it expires.
2. Wait until every instance has the revocation: the same state hash
   everywhere, and `GET /v1/bindings/<identity>` at each instance answers
   `binding.revoked`.
3. Disable the machine's Vault entity, whose alias is the token subject
   `spiffe://<trust domain>/host/<identity>` on the `auth/machine` mount
   (`ergosum revoke` prints the commands), so that the Vault tokens it holds
   stop working; remove the identity from the role if the role names its
   identities.
4. Stop `ergosumd` and delete its state directory, so that no copy of the
   key remains on the disk.
5. Only now release the machine's addresses and overlay node. A released
   address can be handed to someone else; while a binding still names it,
   that machine together with a stolen backup would pass the checks.
6. Remove the machine from monitoring and backups.

## Alerts

`deploy/prometheus/ergosum-alerts.yml` holds a proposal of alerting rules
for these metrics: proven key duplicates and replays, sealed instances,
rejected journal events, stuck outboxes, diverging coverage and stale
checkpoints. Coverage counts as diverging when an instance has not reached,
within 30 minutes, what the most advanced instance had; a peer added
without a sync can stay behind that way for good.

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

Two directories hold a machine's identity: `/var/lib/ergosum` (the identity
key) and `/var/lib/tailscale` (the overlay node key). Whether they belong in
the machine's backups is a trade-off:

- **Included:** a restore brings the machine back working, with its key,
  its binding and its overlay node, and no administrator has to sign a new
  binding. A stolen backup then carries both keys. A copy restored
  elsewhere still fails the callbacks to the place the binding names (`ip`,
  `net`); a copy restored at a bound address, anywhere inside a bound `net`
  prefix, or on a released address that was handed to someone else,
  passes them. `tailnet` alone does not stop such a copy. Protect the
  backup repository like the keys it holds.
- **Excluded:** a stolen backup carries neither key, and a copy of it fails
  everywhere. Every restore then needs a new key, a binding at the next
  epoch and a new overlay node.

To exclude both:

```sh
restic backup --one-file-system --exclude /var/lib/ergosum --exclude /var/lib/tailscale /
```

A `CACHEDIR.TAG` in `/var/lib/ergosum` also keeps the key out of backups
made with `--exclude-caches`.

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
