# Running an authority

The authority (`ergosum serve`) checks machines and signs their tokens. It
is the most sensitive part of an ergosum installation: whoever controls an
authority host can issue tokens for any machine. This page covers
installing, configuring and updating one authority instance. For a second
and further instances, see [Several authority
instances](multiple-authorities.md).

[Getting started](getting-started.md#step-2-set-up-the-authority) walks
through a first installation step by step.

## Requirements

- Linux on x86-64 or ARM64, with systemd or OpenRC, or Docker.
- `ssh-keygen` from OpenSSH 8.1 or later, which `install.sh` uses to check
  the release signature.
- A host of its own if possible; see [Shared host](#shared-host) for the
  alternative.
- TCP 7432 reachable from the machines and the administrators'
  workstations.
- The authority must reach the machines on TCP 7433 at the places their
  bindings name: through the tailnet (with MagicDNS, to resolve tailnet
  names), at their public addresses, or in the local networks it is
  attached to.
- A correct clock (NTP).

## Installing

As root on the authority host. The commands are explained in [Getting
started](getting-started.md#step-2-set-up-the-authority).

```sh
# 1. The binary, checked against the release signature
mkdir -p /root/ergosum-release && cd /root/ergosum-release
base=https://github.com/DunkelCloud/ergosum/releases/latest/download
arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
for f in install.sh SHA256SUMS SHA256SUMS.sig ergosum-linux-$arch; do curl -fsSLO "$base/$f"; done
sh install.sh "$PWD" ergosum

# 2. The service user
useradd --system --user-group --no-create-home \
  --home-dir /var/lib/ergosum-authority --shell /usr/sbin/nologin ergosum-authority

# 3. The signing key; note the fingerprint and the public key it prints
install -d -m 0755 /etc/ergosum
ergosum keygen -out /etc/ergosum/signing.key -encrypt
chgrp ergosum-authority /etc/ergosum/signing.key && chmod 0640 /etc/ergosum/signing.key

# 4. The configuration: /etc/ergosum/serve.yaml (see below)

# 5. The service
v=$(ergosum version | awk 'NR == 1 {print $2}')
curl -fsSL -o /etc/systemd/system/ergosum.service \
  "https://raw.githubusercontent.com/DunkelCloud/ergosum/$v/deploy/systemd/ergosum.service"
systemctl daemon-reload && systemctl enable --now ergosum
ergosum unseal                              # only with an encrypted key
curl -s http://127.0.0.1:7434/healthz       # answers "ok"
```

On Alpine, create the user with `addgroup -S ergosum-authority && adduser
-S -D -H -h /var/lib/ergosum-authority -s /sbin/nologin -G
ergosum-authority ergosum-authority`, and use the OpenRC script
[`deploy/openrc/ergosum`](../deploy/openrc/ergosum) as
`/etc/init.d/ergosum`. With systemd you can also create the user from
[`deploy/sysusers.d/ergosum-authority.conf`](../deploy/sysusers.d/ergosum-authority.conf).

Where the authority keeps its files:

| Path | Owner, mode | Content |
| --- | --- | --- |
| `/usr/bin/ergosum` | root, 0755 | the binary |
| `/etc/ergosum/serve.yaml` | root, 0644 | the configuration |
| `/etc/ergosum/signing.key` | root:`ergosum-authority`, 0640 | the signing key |
| `/etc/ergosum/exchange.key` | root:`ergosum-authority`, 0640 | the exchange key, only for [secrets without Vault](secrets.md) |
| `/var/lib/ergosum-authority/` | `ergosum-authority`, 0700 | `journal.db` (the bindings), `control.sock`, optionally `archive/` |

The authority logs JSON lines to stdout, which systemd puts into the
journal (`journalctl -u ergosum`). `-log-format text` makes them easier to
read by eye.

## Configuration

`/etc/ergosum/serve.yaml`. [`examples/serve.yaml`](../examples/serve.yaml)
shows every setting with comments. The most important ones:

| Setting | Required | Meaning |
| --- | --- | --- |
| `instance` | yes | this instance's name, such as `authority-a`: lower-case letters, digits, `-` and `.`, at most 63 characters; unique and never changed |
| `trust_domain` | yes | the name of your installation, such as `example.com`; the same on every instance and in the admin tool |
| `issuer` | yes | a URL that names your installation, such as `https://ergosum.example.com`; the same on every instance; Vault checks it. Nothing connects to it. |
| `signing_key` | yes | the key file from `ergosum keygen` |
| `listen` | yes | address and port for machines and administrators, normally this host's tailnet address: `100.64.0.10:7432` |
| `registry` | yes | the administrators' keys and how many must approve each change (see [Administrator keys and the registry](administration.md#administrator-keys-and-the-registry)) |
| `callbacks` | no | how the authority calls machines back; see [Network](#network) |
| `authorities_file` | with several instances | the [authority list](multiple-authorities.md#the-authority-list) |
| `replication` | with several instances | the other instances; see [Several authority instances](multiple-authorities.md) |
| `exchange_key_file` | for secrets without Vault | see [Secrets without Vault](secrets.md#preparing-the-authorities) |

Settings with defaults that rarely need a change:

| Setting | Default | Meaning |
| --- | --- | --- |
| `audience` | `vault` | written into the token; Vault checks it |
| `token_ttl` | `30m` | how long a token is valid (10 s to 24 h) |
| `clock_skew` | `2m` | how far a machine's clock may differ |
| `journal` | `/var/lib/ergosum-authority/journal.db` | the database |
| `control_socket` | `/var/lib/ergosum-authority/control.sock` | the local socket for `ergosum unseal` and `ergosum journal` |
| `ops_listen` | `127.0.0.1:7434` | health, metrics and public keys over plain HTTP |
| `listen_all_interfaces` | `false` | allows `listen` on all interfaces (`:7432`); on a public host that exposes the API to the internet |
| `callbacks.port` | `7433` | the machines' callback port |
| `callbacks.timeout` | `5s` | how long a callback may take |
| `compaction` | daily checkpoints, 90 days of observations | see [Checkpoints, compaction and export](multiple-authorities.md#checkpoints-compaction-and-export) |

A change to `serve.yaml` takes effect after a restart (and an unseal). Only
the authority list file is read again on its own.

## The signing key and sealing

Each instance has its own signing key. It signs tokens, identifies the
instance to machines (its fingerprint) and to the other instances, and
secures the instance's TLS connections. **An instance keeps its key for the
life of its name**; a new key means a new instance (see [Changing an
instance's key](multiple-authorities.md#changing-an-instances-key)).

```sh
ergosum keygen -out /etc/ergosum/signing.key            # plain key file
ergosum keygen -out /etc/ergosum/signing.key -encrypt   # passphrase-encrypted
```

`keygen` prints the key ID, the fingerprint for machines and
administrators, and the public key for Vault. It writes the file with mode
0600 for the user who runs it; hand it to the service's group before the
first start:

```sh
chgrp ergosum-authority /etc/ergosum/signing.key && chmod 0640 /etc/ergosum/signing.key
```

The authority refuses to start with a key file that other users may read or
that anyone but its owner may change (mode bits beyond 0640).

**Plain or encrypted?**

- A **plain** key lets the authority start on its own after a reboot. A
  copy of the disk or of a backup contains a usable key.
- An **encrypted** key is protected by a passphrase. After every start the
  instance is **sealed**: it serves only health, metrics and its public
  key, and issues nothing until someone runs, on the same host, as root or
  `ergosum-authority`:

  ```sh
  ergosum unseal          # reads the passphrase from the terminal or stdin
  ```

  A sealed instance does not come back into service on its own; with
  several instances, the others keep issuing meanwhile. `/healthz` answers
  `sealed` (status 503) and the metric `machine_identity_authority_sealed`
  is 1 while it waits; alert on it.

The control socket is the only way to unseal; it is not reachable over the
network.

### Encrypting an existing key

To change a running instance to an encrypted key, without a new key (Vault
and the machines' configuration stay as they are):

```sh
cd /etc/ergosum
ergosum keygen -from signing.key -encrypt -out signing.key.enc   # prints kid and fingerprint: unchanged
chgrp ergosum-authority signing.key.enc && chmod 0640 signing.key.enc
mv signing.key.enc signing.key        # then restart the instance and unseal it
```

`-from` refuses a key that is already encrypted, and checks the result by
decrypting it again. With `-exchange` it does the same for an exchange key,
with the signing key's passphrase. Copies of the plain key in earlier
backups or snapshots stay plain; where they matter, change the key instead.

## Network

| Port (TCP) | Setting | Who connects |
| --- | --- | --- |
| 7432 | `listen` | machines and administrators |
| 7433 | `callbacks.port` | the authority connects to the machines |
| 7434 | `ops_listen` | local monitoring; keep it on `127.0.0.1` |
| 7435 | `replication.listen` | the other authority instances |

**Listener.** `listen` names the address the API binds to, normally the
instance's tailnet address. An address that binds all interfaces (`:7432`,
`0.0.0.0:7432`, `[::]:7432`) is refused unless `listen_all_interfaces:
true` is set.

**How callbacks leave the authority** depends on the check:

- `tailnet` callbacks go to the machine's tailnet name, which the authority
  resolves through its normal DNS (MagicDNS). The address must be inside
  `callbacks.tailnet.prefixes` (default: Tailscale's ranges).
- `ip` callbacks to public addresses leave by the host's normal route. On a
  host with an overlay or an exit node, set `callbacks.ip.source` (and
  `interface`) to the public address and interface, so that the callback
  cannot take the overlay.
- `net` callbacks, and `ip` callbacks to private addresses, need a
  configured network (below).

### Private networks

A `net` check, or an `ip` check on a private address (`10.x`, `172.16-31.x`,
`192.168.x`, IPv6 unique local), only runs at an instance that lists the
network in `callbacks.networks`. Other instances answer "not responsible",
and the machine asks the next one.

```yaml
callbacks:
  networks:
    - cidr: 192.168.10.0/24     # the machines' network
      source: 192.168.10.5      # the address callbacks leave from
      # interface: eth1         # optional; needs CAP_NET_RAW
```

There are two ways to reach such a network:

- **Attached:** the instance has an address in the network itself, on an
  interface of its own or on a VLAN subinterface of a trunk, one per VLAN,
  without routing between them. A callback then reaches only that segment.
  This is the strongest form.
- **Routed:** the instance reaches the networks through a router of your
  own; list them, or one prefix that covers them, with the interface
  towards the router. A check then shows that the machine answers at its
  address as that router delivers it. That is weaker than an attached
  segment and holds only while no other path carries the prefix, such as a
  VPN with an overlapping network. Allow the callback port from `source`
  into those networks.

One instance can serve many networks. List a network on every instance
that should check machines in it; machines with fixed private addresses
(`ip` checks) need the same entries as machines with `net` checks.

## Running in a container

Each release contains the authority as an OCI image archive,
`ergosum-image-linux-amd64.tar` and `ergosum-image-linux-arm64.tar`. The
image runs as a non-root user (UID 65532) and works with a read-only root
filesystem.

1. Download the archive with `SHA256SUMS` and `SHA256SUMS.sig`, and
   [verify them](releasing.md#verifying-a-release).
2. Load it; it is tagged with its version:

   ```sh
   docker load -i ergosum-image-linux-amd64.tar     # loads ergosum:v0.2.1
   ```

3. Create the key and `serve.yaml` in `/etc/ergosum` on the host as
   [above](#installing). The key must belong to UID 65532 and be readable
   by no one else: `chown 65532 /etc/ergosum/signing.key && chmod 0600
   /etc/ergosum/signing.key`.
4. Run it:

   ```sh
   docker run -d --name ergosum --restart unless-stopped --read-only \
     --network host \
     -v ergosum-state:/var/lib/ergosum-authority \
     -v /etc/ergosum:/etc/ergosum:ro \
     ergosum:v0.2.1
   docker exec -it ergosum ergosum unseal          # only with an encrypted key
   ```

Use host networking: with a bridged network, `net` checks and `ip` checks
on private addresses would see only the bridge, and callbacks would leave
from the wrong address. Name the exact version you verified, not `latest`.

## Updating an authority

`install.sh` does not restart an authority, because an instance with an
encrypted key comes back sealed. Update one instance at a time:

```sh
cd "$(mktemp -d)"
base=https://github.com/DunkelCloud/ergosum/releases/latest/download
arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
for f in install.sh SHA256SUMS SHA256SUMS.sig ergosum-linux-$arch; do curl -fsSLO "$base/$f"; done
sh install.sh "$PWD" ergosum         # checks the signature, keeps /usr/bin/ergosum.old
systemctl restart ergosum
ergosum unseal                       # only with an encrypted key
curl -s http://127.0.0.1:7434/healthz
```

The way back is `mv /usr/bin/ergosum.old /usr/bin/ergosum` and another
restart. For a container, load the new image archive, change the image tag,
recreate the container and unseal it.

## Advanced

### Shared host

The authority can run on a host that also runs other services, natively or
as a container. Then whoever controls that host controls the instance and
can issue tokens for any identity: the host becomes as sensitive as the
authority. Ports and callback source addresses are configurable so that the
authority fits next to other services; set `callbacks.ip.source` (and
`interface`, which needs `CAP_NET_RAW`) to the public address and interface,
so that the host's overlay network or exit node cannot carry callbacks to
public addresses. The daemon and the authority run as different users
(`ergosum` and `ergosum-authority`), so that a daemon that is taken over on
the same host reaches neither the signing key nor the journal.

### Callback rules

- `tailnet` callbacks must reach an address inside
  `callbacks.tailnet.prefixes`.
- `ip` and `net` callbacks must neither reach nor leave from an overlay
  address.
- `net` checks run only for prefixes inside `callbacks.networks`, and `ip`
  checks on private addresses (RFC 1918, IPv6 unique local) only for
  addresses inside them; other instances answer "not responsible" and the
  daemon moves on.
- An `ip` check on an address inside `callbacks.networks` leaves by that
  network's route, any other by `callbacks.ip`.
- The authority does not check how a network in `callbacks.networks` is
  reached; that is the attached-or-routed decision above.

### How requests are rated

`key_duplicate`, `replay` and `misdirected` in the audit log or the metrics
are evidence of a copied machine key or a tampered relay; see
[Monitoring](monitoring.md#what-to-alert-on). Requests of an identity
beyond 10, and then one per minute, or while another of its requests is in
flight, are refused as `rate_limited`; a daemon renewing every quarter of
an hour never gets there.

### Upgrading from older releases

- **`unseal_socket` is now `control_socket`**, and `instance` must consist
  of lowercase letters, digits, `-` and `.` (at most 63 characters). A
  journal is pinned to its instance name, so an instance whose name breaks
  that rule starts over under a new name, with a sync from its peers.
- **An authority that ran as user `ergosum`** moves to its own user: stop
  it, move `/var/lib/ergosum/journal.db*` (and the archive) to
  `/var/lib/ergosum-authority/`, run `chown -R ergosum-authority:` on that
  directory, give `signing.key` to the group `ergosum-authority`, and
  adjust `journal`, `control_socket` and `archive` in `serve.yaml` if they
  name the old place.
