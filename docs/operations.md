# Operations

All addresses below are documentation examples (RFC 5737, RFC 3849).

## Users and directories

| Path | Owner, mode | Content |
| --- | --- | --- |
| `/etc/ergosum/` | root, 0755 | `ergosumd.yaml`, `serve.yaml`, `signing.key` (0640, group `ergosum`) |
| `/var/lib/ergosum/` | `ergosum`, 0700 | daemon: `identity.key` (0600), `requests.json`; authority: `journal.db`, `unseal.sock` |
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

Exclude `/var/lib/ergosum/` from backups on machines: a restored machine is
enrolled again with a new key, and a backup must not carry the identity key.

## Daemon

1. Install `ergosumd`, write `/etc/ergosum/ergosumd.yaml`
   (`examples/ergosumd.yaml`).
2. `ergosumd fingerprint` creates the key on first use and prints the
   fingerprint for the binding.
3. Allow TCP 7433 (or the configured callback port) from the authorities'
   source addresses only. The listener is open only while a request is in
   flight.
4. Start the service. The daemon requests a token, writes it to
   `/run/ergosum/token`, and renews it from half its lifetime on.

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
list, and the PEM public key for the token verifier.

With an encrypted key the instance starts **sealed** after every start: it
serves only metrics, health and its public key, and issues nothing until an
operator runs, on the same host,

```sh
ergosum unseal                       # reads the passphrase from the terminal or stdin
```

The unseal socket (`/var/lib/ergosum/unseal.sock`, mode 0600) is the only
way in; it is not reachable over the network. A sealed instance does not
restart into service on its own; another instance keeps issuing meanwhile.
`machine_identity_authority_sealed` is 1 while sealed — alert on it.

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
| `machine_identity_requests_total{result}` | `issued`, `key_duplicate`, `wrong_location`, `foreign_key`, `unknown_identity` |
| `machine_identity_authority_sealed` | 1 while sealed |
| `machine_identity_binding_events_total{outcome}` | write API: `accepted`, `rejected` |

`key_duplicate` is proof that a machine key exists twice and deserves a
critical alert; `wrong_location` a warning.

Audit entries are JSON log lines with `"log_type":"audit"` on stdout — one
per token request (result, identity, request ID, presented key, per-check
outcome, token ID) and per binding write — ready for any log pipeline.
Warnings for `foreign_key` and `unknown_identity` are rate-limited per
identity.

## Writing a binding

A binding event is signed by administrators over its canonical text (see
ADR 0003) with `ssh-keygen`:

```sh
cat > event.txt <<'EOF'
ergosum binding v1
kind binding.set
trust-domain example.com
identity host1.example.com
epoch 1
key SHA256:<fingerprint from ergosumd fingerprint>
check ip 192.0.2.10
check tailnet host1.tailnet.example.com
EOF
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n ergosum-binding event.txt   # each admin
```

The JSON form with all signatures goes to `POST /v1/bindings` on any
instance.

## Token verification in Vault

```sh
vault auth enable -path=machine jwt
vault write auth/machine/config \
  jwt_validation_pubkeys=@authority-a.pem,@authority-b.pem \
  bound_issuer=https://ergosum.example.com
vault write auth/machine/role/host role_type=jwt \
  bound_audiences=vault user_claim=sub \
  bound_claims_type=glob bound_claims='{"sub":"spiffe://example.com/host/*"}' \
  claim_mappings='{"host":"host"}' token_ttl=1h token_max_ttl=1h
```

Vault Agent uses auto-auth method `jwt` with `path=/run/ergosum/token` and
`remove_jwt_after_reading=false`.
