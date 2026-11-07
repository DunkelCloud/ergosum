# Machines: installing and running ergosumd

Every machine that needs an identity runs the daemon `ergosumd`. This page
covers installing it with `install.sh`, updating and removing it, and what
to do when a machine gets no token. [Getting
started](getting-started.md#step-4-enroll-the-machine) shows the first
enrollment in context.

Supported: Linux (x86-64, ARM64) with systemd or OpenRC, and macOS (Apple
Silicon and Intel).

## Enrolling a machine

On the machine, as root (on a Mac, prefix the second line with `sudo`):

```sh
curl -fsSLO https://github.com/DunkelCloud/ergosum/releases/latest/download/install.sh
sh install.sh --domain example.com --anchor 'SHA256:Elq+oe+ce3oYlfjEk7G4WTk4ymiWjlWJJRA5k8TYYsQ@https://100.64.0.10:7432'
```

The same line works for every machine; only the host name differs, and the
script takes it from the machine.

### The two values you need

**`--anchor FINGERPRINT@URL`** tells the machine which authority to talk
to first and which key that authority must present. It consists of:

- the authority's **key fingerprint**, `SHA256:` followed by 43 characters.
  It was printed by `ergosum keygen` when the authority's key was created.
  You can also find it in the authority's log, in the line `starting` at
  every start (`journalctl -u ergosum | grep fingerprint`), or ask whoever
  runs the authority. A hexadecimal fingerprint is not this one.
- an `@`,
- one or more **URLs** of that authority, separated by commas:
  `https://`, an address of the authority that this machine can reach, and
  the port, normally 7432. Usually that is the address in the authority's
  `listen` setting, such as its tailnet address. If the authority answers
  on more than one address (see the note below), list each one the machine
  may use: `https://100.64.0.10:7432,https://192.0.2.10:7432`.

`listen` names a single address. An authority answers on more than one
only with `listen: ":7432"` and `listen_all_interfaces: true` (with a
firewall that admits only your machines and administrators), or through a
port forward.

Put the whole value in single quotes. The machine refuses any authority
that presents another key, as SSH does with a changed host key. After its
first token it learns all other authority instances from the anchor, so one
instance is enough here even if you run several.

**`--domain DOMAIN`** sets the machine's **identity**, its name in ergosum,
to its short host name in that domain: a machine whose host name is `host1`
becomes `host1.example.com`. Use the same domain on all machines. The name
does not have to exist in DNS. If you want to set the name yourself, use
`--identity host1.example.com` instead; without either option the script
takes `hostname -f`, which must then be a full name.

### What the script does

1. It downloads the latest release of `ergosumd` and checks its signature
   and checksum. A machine keeps the release keys in
   `/etc/ergosum/release-signers` for later updates.
2. It creates what is missing: the user `ergosum`, the group
   `ergosum-token`, the state directory `/var/lib/ergosum`, and the service
   (systemd unit, OpenRC script or launchd job).
3. It creates the machine's key, writes `/etc/ergosum/ergosumd.yaml` with
   the identity and the anchor, and connects to the anchor's URLs. If one
   of them presents another key, it stops before writing the configuration;
   an authority that cannot be reached yet does not stop it.
4. It starts the daemon and prints the **binding request** for the
   administrators.

A run that refuses its options, for example because the fingerprint is
malformed, changes nothing. Running the same line again on a machine that
has no token yet changes nothing that is already there and prints the
binding request again; an existing configuration is kept, and `--anchor`,
`--domain` and `--identity` are then ignored. On a machine that has a
token, the same line is an [update](#updating-ergosumd).

### Passing on the binding request

The request is a short text:

```text
# Binding request for host1.example.com, written by ergosumd request at 2026-11-07T10:00:00Z.
# Keep the checks that hold for this machine and delete the others, then
# hand the file to an ergosum administrator, who runs "ergosum bind FILE".
identity host1.example.com
key SHA256:pUlP2fNzgbWeyB0Rkp4FgEBcE2Mq4mYOlUz8Qy2Wq1A
# tailnet name (tailscale status)
check tailnet host1.tailnet.example.com
# Fixed addresses have no lifetime in the kernel. An older dhclient sets DHCP leases without one too: check that each is really fixed.
# eth0: fixed public address
check ip 192.0.2.20
```

Save it as a file (`host1.txt`) and pass it to an ergosum administrator,
who approves it with `ergosum bind host1.txt` (see
[Administration](administration.md#approving-a-new-machine)). You can print
it again at any time:

```sh
sudo -u ergosum ergosumd request > host1.txt
```

Run `ergosumd request` as the service user `ergosum` (on a Mac
`_ergosum`), never as root: a key that root creates belongs to root, and
the service cannot read it. Let the shell write the file with `>` as
above: `-out host1.txt` writes it as the service user, who may not write
to the current directory (such as `/root`).

Once the binding is recorded, the daemon gets its token on its own within
about five minutes.

### Firewall

The authorities call the machine back on **TCP 7433**. Allow this port
from the authorities' addresses, and only from them. With `ufw`, for
example:

```sh
ufw allow proto tcp from 100.64.0.10 to any port 7433
```

The daemon opens the port only while one of its own requests is in
progress. The machine itself needs to reach the authorities on TCP 7432.

### On a Mac

Run the same two lines, the second with `sudo`. The layout follows macOS
conventions:

| Path | Content |
| --- | --- |
| `/usr/local/bin/ergosumd` | the daemon |
| `/etc/ergosum/ergosumd.yaml` | the configuration |
| `/var/db/ergosum/token` | the token |
| `/var/db/ergosum/state/` | the machine's key |
| `/var/log/ergosum/ergosumd.log` | the daemon's log (not rotated) |
| `/Library/LaunchDaemons/io.github.dunkelcloud.ergosumd.plist` | the launchd job |

The service user is `_ergosum`. Things to know:

- **Use `--domain`.** A Mac without a host name of its own reports its
  Bonjour name, such as `hosts-macbook-pro.local`, which the script
  refuses.
- **Application firewall.** If it is on, allow the daemon to receive
  callbacks:

  ```sh
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/local/bin/ergosumd
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /usr/local/bin/ergosumd
  ```

- **Managing the service:**

  ```sh
  sudo launchctl kickstart -k system/io.github.dunkelcloud.ergosumd   # restart
  sudo launchctl print system/io.github.dunkelcloud.ergosumd          # state
  sudo launchctl bootout system/io.github.dunkelcloud.ergosumd        # stop and unload
  ```

- **Tailscale.** The daemon finds the Tailscale CLI in `PATH`, inside the
  app (`/Applications/Tailscale.app`) or from Homebrew. If the request
  shows `# check tailnet NAME`, take the name from `tailscale status` as
  the logged-in user and enter it.
- **Proposed checks.** Addresses of tunnels (`utun`), bridges (Internet
  Sharing, virtual machines) and Apple's peer-to-peer interfaces (`awdl`,
  `llw`) count as virtual: their checks are proposed only as comments.
  Ethernet and Wi-Fi (`en`) come first.
- **The token survives a reboot.** Unlike `/run` on Linux,
  `/var/db/ergosum` is on disk. **Time Machine** backs it up together with
  the key unless you exclude it (see [Backups](#backups)):
  `sudo tmutil addexclusion -p /var/db/ergosum`.
- **Vault Agent** reads the token at `/var/db/ergosum/token`. Its user must
  be in the group `ergosum-token`:
  `sudo dseditgroup -o edit -a USER -t user ergosum-token`.

## Checking a machine

| Question | Linux | Mac |
| --- | --- | --- |
| Is there a token? | `ls -l /run/ergosum/token` | `ls -l /var/db/ergosum/token` |
| What does the daemon say? | `journalctl -u ergosumd -n 50` (OpenRC: syslog) | `tail -n 50 /var/log/ergosum/ergosumd.log` |
| Which version runs? | `ergosumd version` | `ergosumd version` |
| Which key does it have? | `sudo -u ergosum ergosumd fingerprint` | `sudo -u _ergosum ergosumd fingerprint` |
| Do the authorities present the right key? | `sudo -u ergosum ergosumd check` | `sudo -u _ergosum ergosumd check` |
| What is the binding? | `ergosum show host1.example.com` on an admin workstation | same |

The daemon logs `token issued` for every new token and renews it when half
of its lifetime has passed.

## Troubleshooting

### `install.sh` stops

| Message | Cause and fix |
| --- | --- |
| `... in --anchor is no key fingerprint` | The part before `@` is not a fingerprint in the form `SHA256:` + 43 characters. Copy it again from `ergosum keygen` or the authority's log. |
| `identity "..." ... is not a full DNS name` | The host name gives no full name. Add `--domain example.com` or `--identity host1.example.com`. |
| `... is a multicast DNS name (.local)` | A Mac reported its Bonjour name. Add `--domain`. |
| `the authority does not present the key in --anchor` | The URL leads to another authority, or the fingerprint is wrong. Check both. |
| `ssh-keygen (OpenSSH 8.1 or later) is needed` | Install OpenSSH's `ssh-keygen` (Alpine: `apk add openssh-keygen`). |
| `.../ergosumd.yaml does not exist; a new machine needs --anchor` | You ran `install.sh` without options on a new machine. Add `--anchor` and `--domain`. |
| `... exists and stays; --anchor, --identity and --domain are not used` | Not an error: the machine is already configured. To change the anchor or the identity, edit `/etc/ergosum/ergosumd.yaml` and restart the daemon; a new identity needs a new binding. |

### No token

Look at the daemon's log first. A line `token request failed` names the
reason:

| Reason in the log | Meaning | What to do |
| --- | --- | --- |
| `denied` | The authority refused. Before the binding is recorded this is normal. Afterwards a check failed. | The authority's audit log shows which check failed and why (see below). |
| `not_responsible` | No authority instance may run one of the machine's checks: a `net` check or an `ip` check on a private address needs an instance attached to that network. | Add the network to `callbacks.networks` of an instance (see [Private networks](authority.md#private-networks)), or change the check. |
| `clock_skew` | The machine's clock differs too much from the authority's. | Fix the time synchronization (NTP). |
| `rate_limited` | Too many requests for this identity. | Wait a minute. Many of them while the machine is quiet point to a copy of its key. |
| connection errors | The machine does not reach the authority on TCP 7432. | Check the URL in `ergosumd.yaml`, the network and the authority's firewall. |

On the authority, the audit log (`journalctl -u ergosum | grep audit`)
shows the result for the identity and the outcome of every check. Refusals
for `not_responsible` and `clock_skew` leave no audit line, and repeated
failures are logged at most once a minute per identity.

- `unknown_identity`: there is no binding for this name yet, the binding
  is revoked, or the name in the binding differs from the one in
  `ergosumd.yaml`.
- `foreign_key`: the binding names another key, for example after the
  machine was reinstalled. The machine needs a [key
  change](administration.md#everyday-changes).
- `wrong_location`: a callback failed. Usually the firewall blocks TCP 7433,
  or the machine is no longer at the bound address.

A line `callback for a request this machine did not make: the identity key
is in use elsewhere` in the **daemon's** log is serious: another copy of
this machine's key is asking for tokens. Treat it as a security incident;
see `key_duplicate` in [Monitoring](monitoring.md#what-to-alert-on).

## Updating ergosumd

Download the current `install.sh` and run it without options:

```sh
curl -fsSLO https://github.com/DunkelCloud/ergosum/releases/latest/download/install.sh
sh install.sh                      # the latest release
sh install.sh --version v0.2.1     # a specific release
```

The script checks the signature against `/etc/ergosum/release-signers`,
refuses to install an older version (unless you add `--allow-downgrade`),
keeps the old binary as `/usr/bin/ergosumd.old` (on a Mac
`/usr/local/bin/ergosumd.old`), restarts the daemon and waits up to two
minutes for a new token. If no token comes, it puts the old binary back
and restarts it again. Configuration and keys stay untouched.

Roll out to one machine first, then to a few, then to the rest. The metric
`machine_identity_build_info` shows which version runs where.

## All options of install.sh

```text
sh install.sh [OPTIONS] [DIR [BINARY...]]
```

| Option | Meaning |
| --- | --- |
| `--anchor KEY@URL[,URL...]` | a new machine's first authority: key fingerprint and URLs |
| `--domain DOMAIN` | a new machine's identity is its short host name in `DOMAIN` |
| `--identity NAME` | a new machine's identity, given in full (instead of `--domain`) |
| `--version VERSION` | install this release instead of the latest, such as `v0.2.1` |
| `--allow-downgrade` | allow installing an older version |
| `--no-restart` | do not start or restart the daemon; on a new machine everything else is set up and the request printed |
| `--wait SECONDS` | how long an update waits for a new token before it goes back (default 120) |
| `--url URL` | where releases are downloaded from (default `https://github.com/DunkelCloud/ergosum/releases`), for a mirror |
| `--signers FILE` | release keys to check against (default `/etc/ergosum/release-signers`) |
| `--config FILE` | the daemon's configuration (default `/etc/ergosum/ergosumd.yaml`) |

`DIR` installs from release files that are already on the machine instead
of downloading them, for machines without internet access. Download these
files from the release into one directory: `SHA256SUMS`, `SHA256SUMS.sig`,
`ergosumd-linux-amd64` (or the file for your system) and, for a new
machine, `ergosumd.service`, `ergosumd.openrc` and `ergosum.sysusers` (on a
Mac `ergosumd.plist`). Then:

```sh
sh install.sh --domain example.com --anchor '...' /root/ergosum-v0.2.1
```

`BINARY` is `ergosumd` (the default) or `ergosum`; the latter installs the
authority binary (see [Running an authority](authority.md#installing)).

## Removing ergosumd from a machine

First revoke the machine's binding (see
[Decommissioning](administration.md#decommissioning)). Then, on Linux with
systemd:

```sh
systemctl disable --now ergosumd
rm -f /etc/systemd/system/ergosumd.service && systemctl daemon-reload
rm -rf /var/lib/ergosum /run/ergosum
rm -f /etc/ergosum/ergosumd.yaml /usr/bin/ergosumd /usr/bin/ergosumd.old
```

Deleting `/var/lib/ergosum` removes the machine's key, so that no copy of
it is left on the disk. `/etc/ergosum/secrets/` holds sealed secrets, if
the machine had any. The user `ergosum` and the group `ergosum-token` may
stay or be removed with `userdel` and `groupdel`.

On a Mac:

```sh
sudo launchctl bootout system/io.github.dunkelcloud.ergosumd
sudo rm -f /Library/LaunchDaemons/io.github.dunkelcloud.ergosumd.plist
sudo rm -rf /var/db/ergosum /var/log/ergosum
sudo rm -f /etc/ergosum/ergosumd.yaml /usr/local/bin/ergosumd /usr/local/bin/ergosumd.old
```

## Backups

Two directories hold a machine's identity: `/var/lib/ergosum` (its ergosum
key) and, with Tailscale, `/var/lib/tailscale` (its tailnet node key).
Whether they belong in the machine's backups is a trade-off:

- **Included:** a restore brings the machine back working, without a new
  approval. But a stolen backup then carries both keys. A copy restored
  elsewhere still fails the `ip` and `net` checks; a copy restored at the
  bound address, anywhere inside a bound `net` network, or at an address
  that was later given to someone else, passes them. A `tailnet` check
  alone does not stop such a copy. Protect the backup like the keys it
  holds.
- **Excluded:** a stolen backup carries neither key, and a copy of it gets
  no token anywhere. Every restore then needs a new key, a new approval and
  a new tailnet node.

To exclude both with restic:

```sh
restic backup --one-file-system --exclude /var/lib/ergosum --exclude /var/lib/tailscale /
```

If you create a file `CACHEDIR.TAG` in `/var/lib/ergosum` (nothing creates
it for you), backups made with `--exclude-caches` leave the key out as
well. The token in `/run` is in memory and
not part of a backup made with `--one-file-system`.

After a restore: at the same place and with the state directory, nothing
needs to be done. Without the state directory, the machine needs a [key
change](administration.md#everyday-changes); at another place, a new
binding with the new place.

## Advanced

### Files and users on Linux

| Path | Owner, mode | Content |
| --- | --- | --- |
| `/usr/bin/ergosumd` | root, 0755 | the daemon |
| `/etc/ergosum/ergosumd.yaml` | root, 0644 | the configuration |
| `/etc/ergosum/release-signers` | root, 0644 | the release keys that updates are checked against |
| `/var/lib/ergosum/` | `ergosum`, 0700 | `identity.key` (0600), `authorities.json` (the authority list) |
| `/run/ergosum/token` | `ergosum`:`ergosum-token`, 0640 | the token |
| `/run/ergosum/secret.sock` | `ergosum`, 0600 | the socket of `ergosumd secret` |

The daemon runs as `ergosum`. Members of the group `ergosum-token` may read
the token; put the user of Vault Agent into it.

### Installing by hand

1. Install the `ergosumd` binary from a [verified
   release](releasing.md#verifying-a-release).
2. Create the users. With systemd, use
   [`deploy/sysusers.d/ergosum.conf`](../deploy/sysusers.d/ergosum.conf)
   and `systemd-sysusers`. On Alpine:

   ```sh
   addgroup -S ergosum-token
   addgroup -S ergosum
   adduser -S -D -H -h /var/lib/ergosum -s /sbin/nologin -G ergosum ergosum
   addgroup ergosum ergosum-token
   addgroup vault ergosum-token   # the user Vault Agent runs as
   ```

   On a Mac, `_ergosum` is a system account in the local directory
   service: an ID below 500 that no user and no group has, a group
   `_ergosum` with the same ID, no password, the shell `/usr/bin/false`,
   the home `/var/empty`, hidden. `ensure_users_darwin` in
   [`deploy/install.sh`](../deploy/install.sh) shows the `dscl` commands.
3. Write `/etc/ergosum/ergosumd.yaml` (see
   [`examples/ergosumd.yaml`](../examples/ergosumd.yaml) and the reference
   below).
4. Install the service: [`deploy/systemd/ergosumd.service`](../deploy/systemd/ergosumd.service),
   [`deploy/openrc/ergosumd`](../deploy/openrc/ergosumd) or
   [`deploy/launchd/`](../deploy/launchd).
5. Run `sudo -u ergosum ergosumd request > host1.txt` to create the key
   and the binding request, and `sudo -u ergosum ergosumd check` to check
   the authorities' keys.
6. Start the service.

### Configuration reference

`/etc/ergosum/ergosumd.yaml`; every setting with comments is in
[`examples/ergosumd.yaml`](../examples/ergosumd.yaml).

| Setting | Default | Meaning |
| --- | --- | --- |
| `identity` | (required) | the machine's name, a lower-case DNS name |
| `authorities` | (required) | at least one authority: `key` (fingerprint) and `urls` (or one `url`) |
| `state_dir` | `/var/lib/ergosum` (Mac `/var/db/ergosum/state`) | the key and the stored authority list |
| `token_file` | `/run/ergosum/token` (Mac `/var/db/ergosum/token`) | where the token is written |
| `token_group` | `ergosum-token` | group of the token file; `-` leaves it unchanged |
| `metrics_file` | (none) | a node_exporter textfile for [metrics](monitoring.md#machine-metrics) |
| `callback_listen` | `:7433` | address and port for callbacks |
| `addresses` | (detected) | the underlay addresses the daemon reports; see below |
| `overlay_prefixes` | Tailscale's ranges | overlay ranges left out of the detected addresses |
| `request_timeout` | `60s` | how long one token request may take, callbacks included |
| `secret_socket` | `secret.sock` next to the token | socket of `ergosumd secret`; `-` disables it |
| `secret_socket_group` | (none) | a group that may use the secret socket too |

### How the daemon finds the authorities

`authorities` in the configuration needs only one instance, the anchor.
After its first token the daemon takes the [authority
list](multiple-authorities.md#the-authority-list) that the instance serves,
keeps it as `authorities.json` in the state directory, and from then on
tries the listed instances in their order, the configured ones last.

- An anchor that cannot run the machine's `net` checks, or its `ip` checks
  on private addresses, answers "not responsible". A daemon without a list
  then takes the anchor's list at once and asks the instances that can.
- The daemon takes a newer list (higher `serial`) from any listed
  instance, and any list from a configured instance that the list in use
  does not name. So a new anchor in the configuration replaces a list from
  an old installation.
- Of an instance's URLs the daemon tries only those it can reach from its
  own addresses: an overlay address needs an overlay address on the
  machine, IPv4 needs IPv4, other IPv6 needs IPv6. Each connection attempt
  gives up after 5 seconds.
- Prefer addresses to host names in URLs: a name makes every renewal depend
  on DNS.

### Reported addresses

With `addresses` empty, the daemon reports its global unicast addresses
outside the overlay, those of physical-looking interfaces first, at most
16. A host with many bridge or tunnel addresses logs a warning when it has
to leave some out; then list the addresses inside the bound networks in
`addresses`. Addresses listed there count as fixed in a binding request.

### Key changes on the machine

`ergosumd request -new-key` creates the next key next to the current one
(`identity.key.new`) and writes a request for it; the daemon keeps using
the current key until every authority that answers names the next key.
The details are in [Administration](administration.md#how-a-key-change-works).
