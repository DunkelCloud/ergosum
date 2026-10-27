# ADR 0001: Request and callback protocol

- Status: accepted
- Date: 2026-10-27
- Related: [ADR 0002](0002-token-format.md), [ADR 0003](0003-journal-format-and-replication.md)

## Context and problem statement

A machine proves its identity to an authority with two kinds of evidence:
possession of its key, and presence at the places its binding names (an
overlay name, a fixed underlay address, an address inside a permitted
network). The authority checks presence by calling the machine back, in the
spirit of ACME challenges.

A naive callback is open to a relay: an attacker with a copied key sends a
request, the authority calls the real machine, the real machine confirms,
and the token goes to the attacker. The protocol therefore has to bind every
callback to the request that caused it, and the real machine has to be able
to say — verifiably — that it did not make a request.

This ADR fixes the messages between daemon (`ergosumd`) and authority
(`ergosum serve`), their transport, ports, signatures and versioning.

## Decision drivers

- No shared secret: the authority knows only public keys, and a recorded
  exchange is worthless to an eavesdropper.
- A callback is bound to exactly one request; a relayed request cannot be
  confirmed by the real machine.
- A signed "no open request" proves that the key exists twice.
- An ordinary failure (timeout, restart) must never produce a negative
  answer.
- No certificate authority to operate; both sides know each other's keys.
- Callback targets come from the binding only, never from the request.
- Small, auditable code; standard building blocks (TLS 1.3, HTTP, JSON,
  ECDSA P-256).

## Considered options

1. **Signed JSON over HTTPS with key-pinned TLS in both directions**
   (chosen).
2. **gRPC with mutual TLS and a private CA.** Adds a CA, certificate
   lifecycle and a larger dependency tree for four message types.
3. **A single bidirectional connection opened by the daemon** (the authority
   "calls back" over the daemon's own connection). Proves nothing about the
   place: the whole point of a callback is that the authority chooses the
   destination.
4. **JWS for every message.** Equivalent security, but a full JOSE library or
   a partial JWS implementation in security-critical code for no gain over
   the envelope below.

## Decision outcome

Chosen option 1.

### Keys and fingerprints

- Daemon and authority instance each hold one ECDSA P-256 key.
- A key is identified by its **fingerprint**: `SHA256:` followed by the
  unpadded standard base64 of SHA-256 over the DER SubjectPublicKeyInfo.
  Bindings name the daemon key by fingerprint; daemons pin authority
  instances by fingerprint.
- An authority instance is also identified by its **key ID** (`kid`), the
  RFC 7638 JWK thumbprint of its key.

### Transport

- All connections are TLS 1.3. Each side presents a self-signed certificate
  for its long-term key. Certificate chains, names and validity dates are not
  checked; the peer's key must match a pinned fingerprint. The TLS 1.3
  handshake proves possession of that key. Verification runs for every
  connection, including resumed ones; servers disable session tickets.
- Payloads are HTTP/1.1 requests with JSON bodies.

| Connection | Server | Client | Server pins | Client pins |
| --- | --- | --- | --- | --- |
| Token request | authority, port 7432 | daemon | – | authority keys from the daemon config |
| Callback | daemon, port 7433 | authority | authority keys from the daemon config | the bound daemon key |
| Ops (metrics, health, public keys, journal state hash) | authority, port 7434, plain HTTP | operator, scraper | – | – |

All ports are configurable. The callback port of a target may be set per
binding (`192.0.2.10:7440`); otherwise the authority uses its configured
default. The defaults lie in the range 7432–7436, which the IANA registry
lists as unassigned (as of October 2026); they are not registered for
ergosum.

The daemon opens its callback listener only while it has a request in
flight and closes it afterwards.

### Signed envelope

Signed messages travel as

```json
{"payload": "<base64url of the JSON bytes>", "signature": "<base64url of R||S>"}
```

The signature is ECDSA P-256 over `SHA-256(context || 0x00 || payload)`,
encoded as the 64-byte concatenation of R and S. The receiver verifies the
exact payload bytes before it acts on their content, so JSON never needs a
canonical form. The **context** string separates purposes; a signature made
for one never verifies for another:

| Context | Signed by | Message |
| --- | --- | --- |
| `ergosum/v1/token-request` | daemon key | token request |
| `ergosum/v1/callback-response` | daemon key | callback response |
| `ergosum/v1/observation` | instance key | journal observation (ADR 0003) |
| `ergosum/v1/checkpoint` | instance key | journal checkpoint (ADR 0003) |

### Messages

**Token request** — `POST /v1/token`, body: envelope, context
`ergosum/v1/token-request`.

```json
{
  "v": 1,
  "type": "token_request",
  "identity": "host1.example.com",
  "request_id": "<22 chars base64url, 128 bit random>",
  "timestamp": "2026-10-27T20:00:00Z",
  "addresses": ["192.0.2.10", "2001:db8::10"],
  "key": "<base64 DER SubjectPublicKeyInfo>"
}
```

- `identity` is a lower-case FQDN.
- `addresses` are the machine's underlay addresses (at most 16). The
  authority uses them only to pick the destination of a `net` check, and only
  addresses inside the bound prefix.
- `timestamp` must lie within the authority's clock-skew window (default
  ±2 minutes).

**Callback** — `POST /v1/callback` from the authority to the daemon, plain
JSON (authenticated by the pinned TLS client key):

```json
{
  "v": 1,
  "type": "callback",
  "request_id": "<from the request>",
  "nonce": "<43 chars base64url, 256 bit random>",
  "target": "ip:192.0.2.10:7433",
  "authority": "<kid of the calling instance>"
}
```

The **target** names the callback as the authority performs it:
`tailnet:<name>:<port>`, `ip:<address>:<port>`, or
`net:<prefix>:<address>:<port>` (IPv6 in brackets). The daemon rejects a
callback whose `authority` is not the kid of the TLS client key.

**Callback response** — envelope, context `ergosum/v1/callback-response`:

```json
{
  "v": 1,
  "type": "callback_response",
  "status": "confirmed",
  "request_id": "...", "nonce": "...", "target": "...", "authority": "...",
  "timestamp": "2026-10-27T20:00:01Z"
}
```

`status` is `confirmed` if the daemon knows the request ID, otherwise
`no_open_request`. The response repeats request ID, nonce, target and
authority; the authority checks all four and the signature against the bound
key. A signed `no_open_request` from the bound key is proof that the key is
used by someone else; the authority keeps it as evidence (ADR 0003).

**Token response** — `200`:

```json
{"v": 1, "token": "<JWT, ADR 0002>", "expires_at": "...", "server_time": "..."}
```

**Error response** — any other status:

```json
{"v": 1, "error": "denied", "detail": "", "server_time": "..."}
```

| Status | `error` | Meaning |
| --- | --- | --- |
| 400 | `bad_request`, `clock_skew`, `unsupported_version` | malformed or stale request |
| 403 | `denied` | a check failed; the reason is in the audit log only |
| 421 | `not_responsible` | a `net` check needs an instance attached to that network |
| 503 | `unavailable` | instance sealed or journal unavailable |

`denied` deliberately does not say which check failed, so that a prober
learns nothing. The daemon tries the next authority on any error.

### Request IDs across restarts

- The daemon writes a new request ID to disk before the request leaves.
- An open request is retried with the same ID, also after a restart, for at
  most 10 minutes; then the daemon starts a new one.
- The daemon keeps answering `confirmed` for an ID until 10 minutes after
  the request completed.

A crash or timeout therefore leads to a retry or to an unreachable callback,
never to a `no_open_request`.

### Authority procedure

1. Verify the envelope, the timestamp and the identity syntax.
2. Look up the projected binding. No active binding: `unknown_identity`.
3. Fingerprint of `key` differs from the binding, or the signature does not
   verify: `foreign_key`. No callback is made.
4. Plan one callback per bound check; targets and ports come from the
   binding. A `net` check whose prefix is not inside a network attached to
   this instance: answer `not_responsible` before any callback.
5. Run the callbacks (in parallel, each with a timeout, default 5 s). Each
   uses a fresh nonce. For `net`, try up to four reported addresses inside
   the prefix.
6. Any `no_open_request`: `key_duplicate`. Otherwise any callback that is
   unreachable, answers with another key or answers invalidly:
   `wrong_location`. All confirmed: issue the token.

### Reachability rules

- `tailnet` callbacks must reach an overlay address.
- `ip` and `net` callbacks must neither reach an overlay address nor leave
  from one, so that an exit node or overlay route cannot carry an underlay
  check. Source address and interface per check kind are configurable.
- A `net` check runs only on an instance attached to that network.

### Versioning

- Every message carries `"v": 1`, every path starts with `/v1/`, every
  signature context contains `v1`.
- Receivers ignore unknown JSON members within a version; a change that
  older peers must not ignore gets a new version.
- A new version is served on new paths next to the old one until all
  daemons are updated. Unknown `v`: `unsupported_version`.

## Consequences

**Good**

- A copied request is useless, and a relay through the real machine ends
  with a signed proof of key duplication.
- No CA, no certificate renewal; rotating an instance key is a configuration
  change on daemons and in the token verifier.
- The envelope avoids JSON canonicalization and any JOSE dependency.

**Bad**

- The callback listener is reachable from the authorities while a request is
  open; firewalls must allow the authorities' source addresses.
- A relay is proven only if the real machine's listener is open at that
  moment (it is during its own renewals); otherwise the attempt ends as
  `wrong_location`, which still issues nothing.
- `denied` gives operators of a daemon no reason; they need the authority's
  audit log.
- Daemon configuration must list every authority's fingerprint.
