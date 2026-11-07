# Several authority instances

One authority instance is enough to start. A second and further instances
give you:

- **availability:** machines keep getting tokens while one instance is
  down, sealed or being updated;
- **reach:** an instance at each site can check the machines in that
  site's private networks;
- **secrets without Vault** with a threshold of 2 or more, which needs
  that many instances (see [Secrets without Vault](secrets.md)).

The instances form one authority. They have no leader: each holds the whole
journal of bindings, a change approved at any instance reaches all others,
and an instance that was down catches up from its peers.

Each instance is set up as described in [Running an
authority](authority.md), with its own name (`instance`) and its own
signing key. On top of that, every instance needs two things: the
**authority list**, so that machines and administrators find all
instances, and **replication**, so that the instances share their
journals.

## The authority list

The authority list names every instance with its key and the URLs at which
machines reach it. Machines and the admin tool fetch it from any instance,
so a machine configured with one anchor learns all instances by itself.

Write it as `/etc/ergosum/authorities.yaml`
([example](../examples/authorities.yaml)) and name it in `serve.yaml`
as `authorities_file: /etc/ergosum/authorities.yaml`:

```yaml
serial: 1
authorities:
  - key: "SHA256:Elq+oe+ce3oYlfjEk7G4WTk4ymiWjlWJJRA5k8TYYsQ"   # authority-a
    urls:
      - https://100.64.0.10:7432          # tailnet
      - https://192.0.2.10:7432           # public
  - key: "SHA256:vswV23fZQ7IenAozm5haCGS9fD4JU7/wN1Hw2jxB3mc"   # authority-b
    urls:
      - https://100.64.0.11:7432
      - https://[2001:db8::11]:7432
```

- Keep **the same file on every instance**. An instance does not start with
  a file that does not name it.
- List each instance on every path a machine may take (tailnet, public
  IPv4 and IPv6), in order of preference, but only addresses the instance
  really answers on: `listen` names one address, so several URLs need
  `listen: ":7432"` with `listen_all_interfaces: true`, or a port forward.
- **Raise `serial` with every change.** Machines take a list only if its
  serial is higher than the one they have.
- An instance reads the file again when it changes, without a restart or
  an unseal. A file that turns invalid leaves the last good list in place
  and logs an error.

`ergosum authorities` on an administrator's workstation shows what every
instance serves and whether they agree.

## Replication

Every instance names all others in `serve.yaml`:

```yaml
replication:
  listen: "100.64.0.10:7435"       # this instance's tailnet address
  peers:                           # every other instance
    - name: authority-b            # its "instance"
      url: https://100.64.0.11:7435
      key: |                       # its public key, as "ergosum keygen" printed it
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaZjaJWphXwUxBJc8PqqwIeKZaxuL
        bbQp94Nl0sHkl8VEUr8Luu9ddfSg8noe/RblLEjy0EiDssHIrktAEuBgbg==
        -----END PUBLIC KEY-----
```

The instances connect to each other on **TCP 7435** with mutual TLS, using
their signing keys. Allow that port between the instances only.

Name every instance on every instance, even one that this instance does
not connect to directly: its key verifies the events it wrote wherever they
arrive. A peer without `url` is known (its events are accepted when another
instance forwards them) but gets no pushes from here.

The **registry must be the same on every instance**. An instance with a
different registry rejects events that the others accept, and replication
from those instances stops at that event.

## Adding an instance

1. Set up the new instance as in [Running an authority](authority.md), with
   a new `instance` name and its own key, and with all existing instances
   as `peers` (with their `url`). Do not start it yet.
2. On every existing instance, add the new one to `replication.peers`,
   **without `url`** for now, and restart (and unseal) them.
3. Start the new instance, unseal it, and pull the journal from the others
   before anything is written to it:

   ```sh
   ergosum journal sync -from authority-a -from authority-b
   ```

   Several peers give the union of what they hold, so that no single peer
   can hold back a binding.
4. On the existing instances, add the new instance's `url`, so that they
   push to it, and restart them.
5. Add the new instance to the authority list on every instance, and raise
   `serial`.
6. If you use Vault, add the new instance's public key there (see
   [Vault](vault.md#setting-up-vault)); otherwise Vault refuses the tokens
   it issues.

A rebuilt instance keeps its name and key and follows the same steps; it
must sync before it accepts writes, or its new events would reuse sequence
numbers its peers know.

## Removing an instance

1. Take it out of the authority list on every instance and raise `serial`.
2. On every other instance, keep its entry in `replication.peers`, but mark
   it retired and remove its `url`:

   ```yaml
       - name: authority-old
         retired: true      # its events stay valid; it may not connect any more
         key: |
           -----BEGIN PUBLIC KEY-----
           ...
   ```

3. Remove its key from Vault with `machine-auth.sh apply` without its
   `-key`.

A retired instance's key still verifies the events it wrote, which the
others keep and forward, so that a sync between them, or a new instance
built from one of them, still takes its history. It can no longer connect,
gets no pushes, and compaction does not wait for it. **Do not delete the
entry** while any instance still holds events from it: the others would
refuse those events in a sync.

## Changing an instance's key

An instance keeps its key for the life of its name: the key signs its
tokens, journal events and TLS, and peers and machines pin it. A new key is
a new instance:

1. Create the new instance with `ergosum keygen` and a new `instance` name,
   and bring it in (see [Adding an instance](#adding-an-instance)).
2. Add its public key to Vault next to the old one: `machine-auth.sh apply`
   with both `-key` options.
3. Put the new instance into the authority list (and, where the old one is
   the anchor, into the machines' `authorities` in `ergosumd.yaml`), and
   restart the machines' daemons where you changed the configuration.
4. [Remove the old instance](#removing-an-instance), including its key in
   Vault. Vault then refuses its tokens; Vault tokens obtained with them run
   out within the Vault token lifetime.

Step 2 comes before step 3: a token from a key that Vault does not know yet
fails at login.

## Advanced

### Replication settings

```yaml
replication:
  max_page_mib: 32          # largest page sent and accepted; the same everywhere
  origin_quota_mib: 1024    # what another instance's observations may take here
```

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

### Journal state and failures

`ergosum journal state` on an instance (or `GET /v1/journal/state` on its
ops listener) reports the state hash, the coverage and compaction frontier
per origin, and the outbox of every peer. Instances with the same binding
events have the same state hash.

An event that fails verification when it arrives is rejected with an audit
line at level `error` (`"alert"`), counted in
`machine_identity_journal_rejected_total`, and replication from that peer
stops there until the cause is fixed: usually a registry that differs
between the instances, otherwise a forged event. The sender keeps the event
and retries. A failure that says nothing about the event, such as a
database error, is answered with `503` and retried without an alarm; a
lasting one shows as a stuck outbox.

Only a sync takes over the coverage of the checkpoint a peer's journal
starts with, the instance's own sequence counter included; pushes never do.
Sync from peers you trust: a compromised peer could claim a coverage that
makes the instance skip other instances' observations.

Checkpoints only cover origins with a configured key, and the coverage of
an origin that is not configured at all is left out when a checkpoint is
checked.

### Checkpoints, compaction and export

The journal grows with every token request (each one leaves an
*observation*). To keep it small, every instance regularly writes a
**checkpoint**, signed with its key, of every current binding with its
administrators' signatures and of its coverage: daily if the journal
changed, and on `ergosum journal checkpoint`. **Compaction** then deletes
old events, but only when the latest own checkpoint that every peer has
acknowledged covers them, every peer has acknowledged the events
themselves, and their retention has passed; a trigger in the database
refuses to delete anything beyond that point.

```yaml
compaction:
  checkpoint_interval: 24h
  interval: 1h              # how often a checkpoint is considered and compaction runs
  retention:
    observations: 2160h     # 90 days; 0 keeps them
    key_duplicate: 0s       # evidence of a copied key: kept
    bindings: 0s            # binding history: kept; the current bindings live on in the checkpoint
  archive: /var/lib/ergosum-authority/archive   # optional
```

With an archive, compaction first writes the events not yet archived to a
new file there (JSON lines), and deletes only archived events. Under
systemd, an archive outside `/var/lib/ergosum-authority` needs
`ReadWritePaths=` in the unit. A failed checkpoint or compaction is logged
at level `error` and tried again at the next interval; until a run
succeeds, `/healthz` answers `degraded` and
`machine_identity_journal_maintenance_failing` is 1.

Commands on the local instance (through its control socket, as root or
`ergosum-authority`):

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
recovery material of your installation.
