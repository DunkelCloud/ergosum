# How ergosum works

This page explains the parts of ergosum and the words the rest of the
documentation uses. Read it once before you install anything; the
[glossary](#glossary) at the end is the place to come back to when a term
such as *anchor* or *binding* is unclear.

All addresses in this documentation are examples from the ranges reserved
for documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`) or the Tailscale range (`100.64.0.0/10`). Replace them
with your own.

## The parts

ergosum has three kinds of participants, and optionally a fourth:

| Part | Program | Where it runs | What it does |
| --- | --- | --- | --- |
| **Machine** | `ergosumd` (the daemon) | every server, VM or Mac that needs an identity | holds a private key, asks an authority for a token, answers the authority's callbacks, writes the token to a file |
| **Authority** | `ergosum serve` | one or more Linux hosts that you run | checks that a machine is at its approved place and then signs a token for it |
| **Administrator** | `ergosum` (the admin tool) | an administrator's workstation (Linux, macOS, Windows) | approves which machine may get tokens, and from where |
| *Vault or OpenBao* (optional) | `vault`, Vault Agent | your existing Vault | accepts the token as a login and hands out the machine's secrets |

The authority and the admin tool are the same binary, `ergosum`; it does
different things depending on the command (`ergosum serve` on an
authority, `ergosum bind` on a workstation).

## What happens when a machine gets a token

1. **Enrollment.** You install `ergosumd` on the machine with
   [`install.sh`](machines.md). The daemon creates a key pair and prints a
   *binding request*: a short text file with the machine's name, its key
   and the places where it can be reached (its tailnet name, its fixed
   address, its local network).
2. **Approval.** An administrator reviews the request and signs it with
   `ergosum bind`. The signed request becomes a *binding*: "the machine
   `host1.example.com` with this key may get tokens, if it can be reached at
   these places". The authority stores the binding in its *journal*.
3. **Token request.** The daemon asks the authority for a token. The
   request is signed with the machine's key.
4. **Callback.** The authority does not simply trust the request. It
   connects back to the machine at every place the binding names, for
   example to `192.0.2.10` on TCP port 7433, and asks: "did you just make
   this request?". Only the real machine at the real place can answer yes.
5. **Token.** When every callback is confirmed, the authority signs a
   short-lived token (30 minutes by default). The daemon writes it to
   `/run/ergosum/token` and renews it on its own before it runs out.
6. **Use.** Vault Agent logs in to Vault with the token and fetches the
   machine's secrets, or `ergosumd secret` opens a secret that is sealed on
   the machine.

A copy of the machine (a cloned VM, a restored backup on other hardware, a
stolen disk image) has the same key, but it is not at the same place: the
callbacks go to the real machine, and the copy gets no token. If the real
machine is running, it answers "I made no such request", which proves that
its key exists twice. The authority reports that as `key_duplicate`.

## Checks: how a machine's place is described

A binding names one or more *checks*. Each check is one place where the
authority calls the machine back. All checks of a binding must pass.

| Check | Example | Use it for | What a copy of the machine can do |
| --- | --- | --- | --- |
| `tailnet` | `check tailnet host1.tailnet.example.com` | machines in your Tailscale network | pass, if it joins the tailnet as the same node (with the node key from a backup) |
| `ip` | `check ip 192.0.2.10` | a fixed address, public or private | pass only at exactly that address |
| `net` | `check net 198.51.100.0/24` | a machine that gets its address by DHCP in a local network | pass anywhere inside that network |

The daemon proposes suitable checks in its binding request; the
administrator can change them before signing. [Choosing
checks](administration.md#choosing-checks) explains the trade-offs.

`ip` checks on public addresses and `tailnet` checks work from any
authority that can reach the machine. `net` checks and `ip` checks on
private addresses (such as `192.168.x.x` or `10.x.x.x`) only work from an
authority that is attached to that network; see [Private
networks](authority.md#private-networks).

## Ports

| Port (TCP) | Opened by | Reached by | Purpose |
| --- | --- | --- | --- |
| 7432 | authority | machines, administrators' workstations | token requests and binding changes (TLS) |
| 7433 | machine (`ergosumd`) | authorities | callbacks; open only while a request is in flight |
| 7434 | authority, on `127.0.0.1` | local monitoring | health, metrics, public keys (plain HTTP) |
| 7435 | authority | other authority instances | replication of the journal; only with several instances |

All of them can be changed in the configuration.

## Where the values come from

The installation asks for a few values that are created elsewhere. This
table says where to find each one.

| Value | Looks like | Where you get it |
| --- | --- | --- |
| Authority key fingerprint | `SHA256:Elq+oe+ce3oYlfjEk7G4WTk4ymiWjlWJJRA5k8TYYsQ` | printed by `ergosum keygen` when the authority's key was created; the authority also logs it at every start (`journalctl -u ergosum \| grep fingerprint`) |
| Authority URL | `https://100.64.0.10:7432` | `https://`, an address of the authority that the machine can reach, and the port of `listen` in the authority's `serve.yaml` |
| Anchor | `SHA256:Elq+...@https://100.64.0.10:7432` | fingerprint and URL together, joined by `@` |
| Domain | `example.com` | your choice: the DNS domain your machine names belong to; it does not have to resolve |
| Trust domain | `example.com` | `trust_domain` in the authority's `serve.yaml` |
| Administrator's public key | `ssh-ed25519 AAAA... alice@example.com` | the `.pub` file of the administrator's SSH key, such as `~/.ssh/id_ed25519.pub` |
| Authority public key (PEM) | `-----BEGIN PUBLIC KEY-----...` | printed by `ergosum keygen`; also served at `http://127.0.0.1:7434/v1/keys.pem` on the authority |

## Glossary

**Administrator.** A person whose SSH public key is listed in the
authority's registry and who may approve bindings with `ergosum bind`.
Administrators sign with their normal SSH keys, held in `ssh-agent` or on
a security key.

**Anchor.** The first authority a new machine talks to, given to
`install.sh` as `--anchor FINGERPRINT@URL`. The fingerprint tells the
machine which key the authority must present, much like a known SSH host
key: the machine refuses an authority that shows another key, and no
certificate authority is involved. After its first token the machine
learns all other authority instances from the anchor (see *Authority
list*), so one anchor is enough even when you run several instances.

**Approval threshold.** How many different administrators must sign a
change before it takes effect, per kind of change (`binding.set`,
`binding.revoked`). Set in the registry.

**Audit log.** JSON log lines with `"log_type":"audit"` that the authority
writes for every token request and every binding change. See
[Monitoring](monitoring.md#audit-log).

**Authority.** The service that checks machines and signs their tokens
(`ergosum serve`). You can run one *instance* or several; together they
form one authority.

**Authority list.** A list of all authority instances with their keys and
URLs (`authorities_file` in `serve.yaml`). Every instance serves it, and
machines and the admin tool use it to find the other instances. See
[Several authority instances](multiple-authorities.md#the-authority-list).

**Binding.** The approved record that ties a machine's *identity* to its
*key* and its *checks*. Bindings are created, changed and revoked only with
administrators' signatures.

**Binding request.** The text file a machine prints when it is installed
(or when you run `ergosumd request`). It proposes a binding; an
administrator turns it into one with `ergosum bind`.

**Callback.** The connection from the authority back to the machine, on TCP
port 7433, to confirm that the machine itself made a token request and
that it is at the bound place.

**Check.** One place in a binding where the authority calls the machine
back: `tailnet`, `ip` or `net`. See [Checks](#checks-how-a-machines-place-is-described).

**Epoch.** The version number of a machine's binding. Every change (new
key, new address, revocation) gets the next epoch. The admin tool fills it
in.

**Exchange key.** An additional key on an authority instance that is needed
only for [secrets without Vault](secrets.md).

**Fingerprint.** A short form of a public key: `SHA256:` followed by 43
characters. It identifies an authority instance's key (in the anchor and
the admin configuration) or a machine's key (in a binding).

**Identity.** The name of a machine in ergosum, written like a DNS name in
lower case, such as `host1.example.com`. It appears in the binding, in the
token and in Vault. It does not have to resolve in DNS. `install.sh
--domain example.com` makes it the machine's short host name in that
domain.

**Instance.** One running authority (`ergosum serve`) with its own key and
its own name (`instance` in `serve.yaml`, such as `authority-a`).

**Issuer.** A name for your whole ergosum installation in URL form, such as
`https://ergosum.example.com`, written into every token. It is the same on
all instances and is what Vault checks (`bound_issuer`). Nothing connects
to this URL; it only has to be the same everywhere.

**Journal.** The database in which an authority keeps all bindings and a
record (*observation*) of every verified token request, including the
evidence of copied keys (`/var/lib/ergosum-authority/journal.db`).
Several instances copy their journals to each other (*replication*).

**Overlay.** The private network that connects your machines across
locations, such as a Tailscale tailnet. Its addresses (`100.64.0.0/10`)
are treated differently from the *underlay*, the normal network the
machine is attached to.

**Part A.** The sealed form of a secret that `ergosumd secret create`
stores on the machine. It is useless anywhere else. See [Secrets without
Vault](secrets.md).

**Registry.** The list of administrator keys and approval thresholds in
the authority's `serve.yaml`. It decides who may approve bindings.

**Sealed / unseal.** An authority whose signing key is protected by a
passphrase starts *sealed*: it is up, but issues nothing until someone
runs `ergosum unseal` on that host and enters the passphrase.

**Signing key.** The private key of an authority instance
(`/etc/ergosum/signing.key`). It signs tokens and identifies the instance.
Its fingerprint is what machines pin.

**Token.** The short-lived proof of identity a machine receives: a JWT,
valid for 30 minutes by default, in `/run/ergosum/token` (on a Mac
`/var/db/ergosum/token`). Whoever holds the file can use it until it
expires, so only the daemon and Vault Agent may read it.

**Trust domain.** The name of your ergosum installation as it appears in
tokens: a token's subject is `spiffe://<trust domain>/host/<identity>`.
Usually your main domain, such as `example.com`. All instances and the
admin tool use the same one.
