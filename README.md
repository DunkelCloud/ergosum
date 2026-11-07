# ergosum

**Short-lived machine identities that a cloned machine does not get.**

ergosum gives each machine an identity token only after calling it back at
the places it was bound to: its tailnet name, a fixed address, an address
in a permitted network. A cloned VM image, a stolen backup or a copied key
gets no token anywhere else, and a copy that relays through the real
machine is detected.

The token logs the machine in to HashiCorp Vault or OpenBao, without a
long-lived secret on its disk. Without Vault, the same checks open a sealed
secret, such as a backup password, only on that machine at its place.

*cogito, ergo sum*: the machine answers the callback at its place,
therefore it is who it claims to be.

## Why

To get its secrets, a machine has to prove who it is, and the proof is
usually one more secret on its disk: an AppRole secret ID, an API token, a
private key. Whoever copies the disk, the VM image or a backup holds the
same proof. Cloud VMs can fall back on their provider's instance identity;
bare-metal servers, rented VPS and machines at home or in the office have
nothing like it.

ergosum adds what a copy cannot take along: the machine's place.

## What you get

- **Short-lived tokens.** A JWT (ES256, SPIFFE JWT-SVID layout), valid for
  30 minutes by default, which the daemon renews on its own. A revoked
  binding gets no further token.
- **Detected copies.** When a copied key asks for a token, the real machine
  answers the callback with a signed "no open request": proof that the key
  exists twice.
- **Vault and OpenBao as they are.** Their built-in JWT auth method checks
  the token, and Vault Agent hands out every further credential. Any other
  service can check it against the authority's JWKS.
- **Secrets without Vault.** `ergosumd secret` seals a secret on the
  machine in the manner of Tang and Clevis: it opens only after the machine
  has passed its checks at a threshold of authority instances. It works as
  the password command of restic or borg.
- **No single point of trust.** Every binding needs SSH signatures from as
  many administrators as you require, on security keys if you like. The
  authority instances replicate a signed journal without a leader.
- **Builds you can check.** Static Go binaries, reproducible builds, signed
  releases.

## How it works

```text
 ergosumd on the machine              authority (ergosum serve)
           |                                      |
           |--- token request, signed ----------->|  looks up the binding
           |                                      |  in the signed journal
           |<-- callback at every bound place ----|
           |--- signed "confirmed" -------------->|
           |<-- JWT, valid for 30 minutes --------|
           |
           +--- JWT login through Vault Agent ---> Vault or OpenBao
```

A small daemon on each machine holds a key pair and asks an authority for a
token. The authority looks the identity up in its binding journal, verifies
the request signature and calls the machine back at every place the binding
names. Only when every callback confirms does it sign the token. Each
callback is bound to the one request that caused it, so the real machine
never confirms a request it did not make.

Bindings are approved by administrators with SSH signatures, made through
the SSH agent or `ssh-keygen -Y sign`; a registry on every authority
instance sets how many distinct administrators must sign each kind of
change. Each change is one text file: the machine writes the request, and
each administrator runs `ergosum bind` on it until the approvals suffice.
The authority instances replicate their binding journal among each other
without a leader, verify every event before they store it, and shorten it
through signed checkpoints.

## Status

Early development. Interfaces and formats are described in
[`docs/adr/`](docs/adr) and may still change. Secrets without Vault
(`ergosumd secret`) are in every release since `v0.2.0`.

## Getting started

A first installation has four steps. [Getting
started](docs/getting-started.md) walks through each of them with every
command; [How ergosum works](docs/concepts.md) explains the terms.

1. **Run an authority.** The authority is the service that checks machines
   and signs their tokens. You run it yourself, on a Linux host or as a
   container. It gets a signing key of its own, and its *fingerprint*
   (`SHA256:...`) is how machines recognize it.
2. **Enroll a machine.** On each machine, as root, one script installs the
   daemon `ergosumd`:

   ```sh
   curl -fsSLO https://github.com/DunkelCloud/ergosum/releases/latest/download/install.sh
   sh install.sh --domain example.com --anchor 'SHA256:...@https://192.0.2.10:7432'
   ```

   `--domain` is the domain of the machine's name in ergosum: `host1`
   becomes `host1.example.com`. `--anchor` names the authority the machine
   talks to first: its fingerprint, an `@`, and its address and port. The
   script checks the release signature, sets up the service, starts it and
   prints a *binding request*: the machine's name, key and the places where
   it can be reached. It works the same on a Mac (with `sudo`) and updates
   the machine later. All options: [Machines](docs/machines.md).
3. **Approve the machine.** An administrator saves the request as a file
   and signs it with `ergosum bind host1.txt`. From then on the machine
   gets its token on its own and keeps it in `/run/ergosum/token` (on a
   Mac `/var/db/ergosum/token`).
   [Administration](docs/administration.md) explains how to choose the
   places to check.
4. **Use the token.** Vault Agent logs in to Vault or OpenBao with it
   ([Vault](docs/vault.md)), or `ergosumd secret` opens a sealed secret
   such as a backup password without Vault ([Secrets without
   Vault](docs/secrets.md)).

## What it does not do

- It does not protect a machine that is taken over while it runs: root on
  the machine can use its key, its token and its secrets, as the machine
  itself can.
- A clone that takes the machine's place passes its checks: at the bound
  address, or anywhere in the network a `net` check names. The place is the
  identity.
- The token is a bearer token: whoever copies it can use it until it
  expires.
- There is no hosted service: the authorities are yours to run.

## Components

| Binary     | Runs on            | Purpose |
|------------|--------------------|---------|
| `ergosumd` | every machine      | key pair, token requests, callback listener, token file; `request` for its binding, `secret` for secrets without Vault |
| `ergosum`  | authority instances, administrators | `serve` (authority), `unseal`, `keygen`, `journal`; `bind`, `revoke`, `show`, `list`, `authorities`; `release` |

Both are static Go binaries without cgo for `linux/amd64` and `linux/arm64`.
`ergosumd` is also built for macOS (Apple Silicon and Intel), so that a Mac
can be a machine; `ergosum` is built for Windows and macOS as well, for
administrators' machines.
The authority also ships as an OCI image that runs as a non-root user on a
read-only root filesystem.

## Documentation

Start at the [documentation overview](docs/README.md). The main pages:

- [How ergosum works](docs/concepts.md): the parts, checks, ports, where
  the installation values come from, and a glossary
- [Getting started](docs/getting-started.md): a first installation, step by
  step
- [Machines](docs/machines.md): `install.sh`, the Mac, troubleshooting,
  updates, backups
- [Administration](docs/administration.md): approving and changing
  bindings
- [Running an authority](docs/authority.md) and [Several authority
  instances](docs/multiple-authorities.md)
- [Vault and OpenBao](docs/vault.md), [Secrets without Vault](docs/secrets.md),
  [Monitoring](docs/monitoring.md)
- [Releases](docs/releasing.md): verifying downloads; making a release
- [Architecture decisions](docs/adr/): protocol, token format, journal and
  replication, releasing secrets without Vault
- Example configuration: [`examples/`](examples); service definitions,
  alert rules and the Vault setup script: [`deploy/`](deploy)

## Building

```sh
scripts/build.sh dist
go test ./...
```

`scripts/build.sh` builds with the toolchain named in `go.mod`, which Go
fetches if needed. `GOOS` and `GOARCH` select the target; `VERSION` and
`COMMIT` are stamped into the binaries. The same commit and settings give
the same bytes on Linux, macOS and Windows (in Git Bash), so anyone can
rebuild a published binary and compare it.

Releases are signed with an SSH key listed in
[`release-signers`](release-signers); see [Releases](docs/releasing.md).

## License

Apache License 2.0; see [`LICENSE`](LICENSE).
