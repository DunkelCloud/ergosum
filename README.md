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
(`ergosumd secret`) are on `main` and in the pre-release `v0.2.0-rc.1`
(`install.sh --version v0.2.0-rc.1`), not yet in a release.

## Getting started

You need one authority instance you run yourself (Linux, native or as an
OCI image) and machines on Linux or macOS that reach it on TCP 7432 and
that it can call back on TCP 7433, over the tailnet or at a fixed address.

1. **Run an authority.** `ergosum keygen` creates its signing key, a
   `serve.yaml` ([example](examples/serve.yaml)) names its listener, its
   callbacks and the administrators' keys, and `ergosum serve` runs it; see
   [Operations](docs/operations.md#authority).
2. **Enroll a machine**, as root, with the machines' domain and the
   authority's key fingerprint and URL:

   ```sh
   curl -fsSLO https://github.com/DunkelCloud/ergosum/releases/latest/download/install.sh
   sh install.sh --domain example.com --anchor 'SHA256:...@https://192.0.2.10:7432'
   ```

   The script installs `ergosumd` from the latest signed release, sets up
   its user, service and configuration, starts it and prints the binding
   request for the administrators. The same script updates the machine
   later. On a Mac the same two lines enroll it, the second with `sudo`
   (see [Operations](docs/operations.md#on-a-mac)).
3. **Approve the binding.** Save the request as a file and run
   `ergosum bind host1.txt` on an administrator's machine. The request
   proposes a fixed address, public or private, as an `ip` check, and the
   network of an address from DHCP as a `net` check, which a clone
   anywhere in that network passes as well
   ([Choosing checks](docs/operations.md#choosing-checks)). Once the
   approvals suffice, the daemon receives its token on its own and keeps it
   in `/run/ergosum/token` (on a Mac `/var/db/ergosum/token`).
4. **Use it.** Let Vault Agent log in with the token
   ([`examples/vault-agent`](examples/vault-agent); Vault setup and
   rollback: [`deploy/vault/machine-auth.sh`](deploy/vault/machine-auth.sh)),
   or seal a secret without Vault at instances that hold an exchange key
   ([Operations](docs/operations.md#secrets-without-vault)):

   ```sh
   printf '%s\n' "$RESTIC_PASSWORD" | ergosumd secret create restic -threshold 2
   RESTIC_PASSWORD_COMMAND='ergosumd secret get restic' restic snapshots
   ```

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

- [Operations](docs/operations.md): installation, modes of operation, unsealing, secrets without Vault, metrics, audit, Vault
- [Releases](docs/releasing.md): verifying, installing and updating signed releases; making one
- [Architecture decisions](docs/adr/): protocol, token format, journal and replication, releasing secrets without Vault
- Example configuration: [`examples/`](examples), including Vault Agent;
  service definitions for systemd, OpenRC and launchd: [`deploy/`](deploy)
- Vault setup and rollback: [`deploy/vault/machine-auth.sh`](deploy/vault/machine-auth.sh)

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
