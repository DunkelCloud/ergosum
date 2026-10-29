# ergosum

*cogito, ergo sum* — a machine answers the callback at its place, therefore it is who it claims to be.

ergosum gives every machine its own short-lived identity. A small daemon on
each machine holds a key pair and requests an identity token from an
authority. The authority looks the identity up in a signed binding journal,
verifies the request signature and calls the machine back at the places the
binding names: its overlay name, a fixed underlay address, or an address
inside a permitted network. Only when every callback confirms does the
authority sign a short-lived JWT (ES256, JWT-SVID layout, audience `vault`).
HashiCorp Vault (or OpenBao) verifies the token with its built-in JWT auth
method, and Vault Agent hands out every further credential.

A copied disk image, a stolen backup or a copied key does not receive a token
outside the networks it was bound to, and a relay through the real machine is
detected: the real machine answers a callback for a request it never made with
a signed "no open request".

## Status

Early development. Interfaces and formats are described in
[`docs/adr/`](docs/adr) and may still change.

## Components

| Binary     | Runs on            | Purpose |
|------------|--------------------|---------|
| `ergosumd` | every machine      | key pair, token requests, callback listener, token file; `request` for its binding |
| `ergosum`  | authority instances, administrators | `serve` (authority), `unseal`, `keygen`, `journal`; `bind`, `revoke`, `show`, `list` |

Bindings are approved by administrators with SSH signatures, made through
the SSH agent or `ssh-keygen -Y sign`; a registry on every authority
instance sets how many distinct administrators must sign each kind of
change. Each change is one text file: the machine writes the request, and
each administrator runs `ergosum bind` on it until the approvals suffice.
The authority instances replicate their binding journal among each other
without a leader, verify every event before they store it, and shorten it
through signed checkpoints.

Both are static Go binaries without cgo for `linux/amd64` and `linux/arm64`;
`ergosum` is also built for Windows and macOS, for administrators' machines.
The authority also ships as an OCI image that runs as a non-root user on a
read-only root filesystem.

## Documentation

- [Operations](docs/operations.md): installation, modes of operation, unsealing, metrics, audit, Vault
- [Architecture decisions](docs/adr/): protocol, token format, journal and replication
- Example configuration: [`examples/`](examples), including Vault Agent;
  service definitions for systemd and OpenRC: [`deploy/`](deploy)
- Vault setup and rollback: [`deploy/vault/machine-auth.sh`](deploy/vault/machine-auth.sh)

## Building

```sh
CGO_ENABLED=0 go build -o dist/ ./cmd/...
go test ./...
```
