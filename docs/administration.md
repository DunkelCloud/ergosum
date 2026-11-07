# Administration: approving and changing bindings

A machine gets tokens only for a **binding** that administrators have
signed: its identity, its key and the places (checks) where the authority
may call it back. This page shows how administrators create, change and
revoke bindings with the admin tool `ergosum`.

Every change follows the same pattern: there is one **text file** for the
change, each administrator who approves runs `ergosum bind FILE` on it, and
once enough of them have signed, the tool records the change at the
authorities.

## Setting up the admin tool

The admin tool runs on Linux, macOS and Windows.

1. **Install it.** Download `ergosum-linux-amd64`, `ergosum-darwin-arm64`,
   `ergosum-darwin-amd64`, `ergosum-windows-amd64.exe` or the ARM64
   variant from the [releases
   page](https://github.com/DunkelCloud/ergosum/releases/latest), rename
   it to `ergosum` (`ergosum.exe`), make it executable and put it in your
   `PATH`. [Verifying a release](releasing.md#verifying-a-release) shows how
   to check it.
2. **Have an SSH key** whose public key is listed in the authorities'
   registry (see [Administrator keys and the
   registry](#administrator-keys-and-the-registry)). Load it into your SSH
   agent, or let the tool ask for its passphrase.
3. **Write the configuration.** `ergosum help` names the file it reads:
   `~/.config/ergosum/admin.yaml` on Linux, `~/Library/Application
   Support/ergosum/admin.yaml` on macOS, `%AppData%\ergosum\admin.yaml` on
   Windows. The environment variable `ERGOSUM_ADMIN_CONFIG` names another
   file.

   ```yaml
   trust_domain: example.com               # as in the authorities' serve.yaml
   sign_key: ~/.ssh/id_ed25519.pub         # your public key
   authorities:                            # one is enough if they serve an authority list
     - url: https://100.64.0.10:7432
       key: SHA256:Elq+oe+ce3oYlfjEk7G4WTk4ymiWjlWJJRA5k8TYYsQ   # the instance's fingerprint
   ```

4. **Test it** with `ergosum list` and `ergosum authorities`.

Your workstation needs TCP 7432 to every authority instance.

## Approving a new machine

When a machine is installed, `install.sh` prints a binding request (see
[Machines](machines.md#passing-on-the-binding-request)). Save it as a file,
for example `host1.txt`, and run:

```sh
ergosum bind host1.txt
```

The request contains the machine's proposal:

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

- `identity` is the machine's name.
- `key` is the fingerprint of the machine's key. If you want to be sure
  that the file really comes from that machine, compare it with the output
  of `sudo -u ergosum ergosumd fingerprint` on the machine.
- each `check` line is a place where the authority will call the machine
  back. **All of them must pass** for every token.

Before you confirm, check that the checks describe where the machine really
is (see [Choosing checks](#choosing-checks)). You can edit the file: delete
a check, add one, or remove the `#` in front of a check the daemon proposed
only as a comment. Lines starting with `#` are comments.

The tool then:

1. adds what the change needs (kind, trust domain, the next epoch),
2. shows the text to sign and how it differs from the current binding,
3. asks you, signs with your key and appends the signature to the file,
4. records the binding at the authorities once there are enough
   signatures, and notes where at the end of the file.

If the registry requires two approvals, the tool says `1 of 2 approvals`
and that you should pass the file on. The next administrator runs the same
`ergosum bind host1.txt` on the same file.

The machine needs no further step: it gets its token on its own within
about five minutes. Check that the token appears (see [Checking a
machine](machines.md#checking-a-machine)) and that the authority's audit
log shows `issued`.

If you use Vault, give the machine its secrets there, and add its identity
to the Vault role if the role names identities (see [Vault](vault.md)).

## Choosing checks

| Check | Use it for | A copy of the machine's key... |
| --- | --- | --- |
| `tailnet NAME` | machines in your tailnet | ...passes if it joins the tailnet as the same node, for example from a backup that includes `/var/lib/tailscale` |
| `ip ADDRESS` | a fixed address, public or private | ...passes only at exactly that address |
| `net PREFIX` | a local network in which the machine gets its address by DHCP | ...passes anywhere inside that network |

Use the strictest check that fits. A machine with a fixed address gets an
`ip` check; a machine with a changing address in a local network gets a
`net` check for that network. Several checks together are stronger: a copy
has to pass all of them.

A copy is caught in two ways. While the real machine runs, it answers the
callback at its place with "I made no such request", which proves the copy
(`key_duplicate`). While the real machine is off, the copy fails unless it
takes over the machine's address.

`ergosumd request` proposes checks as follows:

- its tailnet name as a `tailnet` check;
- fixed addresses as `ip` checks, public and private alike. On Linux it
  recognizes addresses from DHCP or SLAAC by their limited lifetime
  (`dynamic` in `ip addr`). An older dhclient sets leases without a
  lifetime, which then look fixed: bind the network instead where the
  address can change;
- the networks of private addresses from DHCP as `net` checks;
- public addresses from DHCP or SLAAC, IPv6 addresses that are not fixed,
  and addresses of virtual interfaces (tunnels, bridges) only as comments.

Things to watch:

- A `net` check, and an `ip` check on a private address, only works if an
  authority instance is attached to that network (`callbacks.networks`,
  see [Private networks](authority.md#private-networks)). Other instances
  answer "not responsible".
- An `ip` check on an IPv6 address needs authorities that reach the
  machine over IPv6. Delete it where the authorities have only IPv4.
- On macOS, which does not tell fixed from leased addresses, public
  addresses are proposed as `ip` checks and private ones as `net` checks.
- Addresses listed in the daemon's `addresses` setting count as fixed.

## Everyday changes

| Situation | Who does what |
| --- | --- |
| **New machine** | `install.sh` on the machine, then `ergosum bind FILE` ([above](#approving-a-new-machine)) |
| **New key**: routine rotation, machine reinstalled or restored without its state directory, or after a `key_duplicate` alert | on the machine `sudo -u ergosum ergosumd request -new-key > host1.txt`, then `ergosum bind host1.txt` |
| **Machine moved**: new address, other network, an additional check | on the machine `sudo -u ergosum ergosumd request > host1.txt`, or on the workstation `ergosum show -out host1.txt host1.example.com` and edit the checks; then `ergosum bind host1.txt` |
| **Machine renamed** | enroll it under the new name, revoke the old name |
| **Machine retired** | `ergosum revoke host1.example.com`, then [decommission](#decommissioning) it |
| **Old name used again** | as for a new machine; `ergosum bind` shows "revoked in epoch k" and continues at k+1 |
| **Machine restored from a backup** | same place with its state directory: nothing; without the state directory: new key; at another place: machine moved |
| **Look something up** | `ergosum show NAME` (epoch, key, checks, who approved), `ergosum list` (all bindings) |

**Revoking.** `ergosum revoke host1.example.com` shows what it ends,
writes `host1.example.com.revoke.txt` and continues like `ergosum bind`. If
the registry requires more approvals, another administrator runs `ergosum
bind` on that file. Every authority instance stops issuing tokens as soon
as the revocation reaches it; a token already issued stays valid until it
expires (30 minutes by default).

**Changes that overlap.** A change file is made for one epoch of the
binding. If another change is recorded first, the file is stale: the tool
says so and refuses it, and so does the authority. Start again from a new
request or from `ergosum show`. This way no change silently replaces
another.

## Decommissioning

1. `ergosum revoke NAME`, with as many approvals as the registry requires.
2. Wait until every authority instance has the revocation: `ergosum show
   NAME` shows it without reporting that the instances disagree. (In
   detail: every instance reports the same state hash in `ergosum journal
   state`, and `GET /v1/bindings/<identity>` at each instance answers
   `binding.revoked`.)
3. If you use Vault: disable the machine's Vault entity, so that Vault
   tokens it still holds stop working (`ergosum revoke` prints the
   commands), and remove the identity from the Vault role if the role names
   identities.
4. Stop `ergosumd` and delete its state directory, so that no copy of the
   key remains (see [Removing ergosumd](machines.md#removing-ergosumd-from-a-machine)).
5. Only now release the machine's addresses and its tailnet node. A
   released address can be given to someone else; while a binding still
   names it, a machine there together with a stolen backup would pass the
   checks.
6. Remove the machine from monitoring and backups.

## Advanced

### The change file

The file is the canonical text of the change (ADR 0003), line by line, in
any order, with `#` comments. Line endings and encoding (UTF-8, or UTF-16
as Windows PowerShell writes it) do not matter. After `ergosum bind` it
looks like this:

```text
# Binding request for host1.example.com, written by ergosumd request at 2026-11-07T10:00:00Z.
# Keep the checks that hold for this machine and delete the others, then
# hand the file to an ergosum administrator, who runs "ergosum bind FILE".
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

The tool refuses what would otherwise fail later or go unnoticed:

- If the text changed after a signature, it names the signature that no
  longer matches. Undo the change, or remove the signature and sign again.
- If the binding changed between making the file and recording it, the
  tool stops, and so does the authority (`409`). Start with a new file.
- A key that the registry does not allow for this kind of change cannot
  sign, and a key signs only once.

### How the tool talks to the authorities

The tool first asks the configured authorities for their [authority
list](multiple-authorities.md#the-authority-list) and adds the instances it
names, each at the first of its URLs reachable from this workstation; the
lists must agree. `ergosum authorities` shows the lists, which instances are
not configured here and which configured ones the list lacks.

It then reads from every authority and insists that those that answer
agree: on the trust domain (which must be the configured one), on the
approvals, and on the binding at hand. If they disagree, `bind`, `revoke`
and `show` stop and name both answers. That happens for a moment while
replication carries a change, and otherwise means that one authority is
wrong. `list` names the identities they disagree on. If only one authority
answers, the tool says that it could not compare.

A change goes to the first reachable authority; the tool then asks the
others for a few seconds whether they have it, and says which do not yet.
`-trust-domain`, `-authority` and `-authority-key` replace the configured
values for one command.

### How the tool signs

`sign_key` is a public key (a file, or the key line itself) whose private
key the SSH agent holds: `ssh-agent` through `SSH_AUTH_SOCK`, on Windows
the OpenSSH agent service (`Get-Service ssh-agent`) or another agent whose
pipe `SSH_AUTH_SOCK` names. A public key in the SSH2 format, as PuTTYgen
exports it, works as well. If the agent does not hold the key, the tool
signs with `ssh-keygen -Y sign` and the private key file next to the public
one, which asks for the passphrase or the touch of a security key. A
private key file as `sign_key` is signed that way, too. `-sign-key`
overrides the configuration for one command; `-yes` signs without asking.

### Signing by hand

If the tool cannot sign, sign with `ssh-keygen` directly and add the
signature to the file:

```sh
ergosum bind -text event.txt host1.txt   # completes host1.txt, writes the text to sign
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n ergosum-binding event.txt
cat event.txt.sig >> host1.txt           # PowerShell: Get-Content event.txt.sig | Add-Content host1.txt
ergosum bind host1.txt                   # checks the signature, records at the threshold
```

`-f` takes the private key or, with the key in the agent, its public key in
OpenSSH format. A public key in the SSH2 format (RFC 4716, as PuTTYgen
exports it) fails in `ssh-keygen` with a misleading "No such file or
directory"; `ssh-keygen -i -f key.pub > key-openssh.pub` converts it. Sign
`event.txt` exactly as it is: opened and saved by an editor with CRLF line
endings it is a different text. `ergosum bind` recognizes a signature made
over the CRLF form, or in another namespace than `ergosum-binding`, and
says so.

Without the tool at all, post the JSON form of the event (ADR 0003) with
all signatures to `POST /v1/bindings` on any instance.

### How a key change works

`ergosumd request -new-key` creates the next key next to the current one
(`identity.key.new`) and writes a request for it; run again, it names the
same next key. The daemon keeps using the current key. Before each request
it asks every authority for the binding; once every authority that answers
names the next key, it switches to it; an authority that does not answer
does not hold it back. The old key stays as `identity.key.old` until a token is issued for
the new one, and is then deleted.

If every authority refuses the new key (403), the daemon goes back to the
old key, keeps the new one as `identity.key.new` and asks again after ten
minutes; an outage changes nothing. `ergosum bind` shows the change as "key
old -> new"; the old key is invalid from the moment the binding is
recorded. The metric `machine_identity_key_change_pending` is 1 while the
next key waits. After a restore without the state directory there is no
old key: `ergosumd request` simply creates a new one.

### Administrator keys and the registry

The registry in every instance's `serve.yaml` names the administrator keys
and, for each kind of change, how many of them must sign:

```yaml
registry:
  admins:
    alice: "sk-ssh-ed25519@openssh.com AAAA... alice@example.com"
    bob: "ssh-ed25519 AAAA... bob@example.com"
  approvals:
    binding.set:     { threshold: 2, keys: [alice, bob] }
    binding.revoked: { threshold: 1, keys: [alice, bob] }
```

Whoever controls enough administrator keys, or the registry of an
instance, can bind any identity to any key. Treat both as the most
sensitive part of the installation:

- Keep administrator keys on security keys (`sk-ssh-ed25519`,
  `sk-ecdsa-sha2-nistp256`), which also require a touch for each signature,
  or at least passphrase-protected, and never on an authority host.
  Allowed are ed25519, ECDSA, RSA with at least 2048 bits, and security
  keys; `ssh-dss` keys and certificates are refused.
- Set the threshold for `binding.set` to 2 or more where two administrators
  are available.
- Change the registry on every instance through the same reviewed
  deployment. Until all instances run the new registry, those with the old
  one reject events signed only by new keys, and replication stops at such
  an event (see [Several authority instances](multiple-authorities.md)).
- Before an administrator key leaves the registry, have the remaining
  administrators approve again, at the next epoch, every binding that only
  that key approved, and let compaction remove the older events (retention
  for `bindings`). Old events approved only with a removed key would stop a
  sync.
- A signed binding event is valid in every journal of its trust domain,
  and anyone who reaches the API can write it to an instance where the
  identity's current epoch is lower. When the journals of a trust domain
  start over (after a trial, or a loss without an export), start them with
  **new administrator keys**. Otherwise every event signed before, such as
  an old machine key, a test identity or a revocation, can come back and
  win against the new bindings.
