# ADR 0001: Request and callback protocol

- Status: proposed
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
- A callback is bound to exactly one request; a relayed or replayed request
  cannot be confirmed by the real machine, not even with a request ID copied
  from a disk image.
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
| Token request | authority, port 7432, overlay address | daemon | – | authority keys from the daemon config and its authority list |
| Callback | daemon, port 7433 | authority | authority keys from the daemon config and its authority list | the bound daemon key |
| Replication (journal push and pull, ADR 0003) | authority, port 7435, overlay address | peer authority | the configured peers' keys | the peer's key |
| Ops (metrics, health, public keys, journal state hash) | authority, port 7434, plain HTTP | operator, scraper | – | – |

All ports are configurable. The callback port of a target may be set per
binding (`192.0.2.10:7440`); otherwise the authority uses its configured
default. The defaults lie in the range 7432–7436, which the IANA registry
lists as unassigned (as of October 2026); they are not registered for
ergosum.

The token request and replication listeners have no default address: the
configuration must name one, normally the instance's overlay address.
Binding all interfaces needs an explicit `listen_all_interfaces`, so that a
public host does not expose the API by accident.

Operator commands (unseal, journal checkpoint, compaction, sync and export)
reach an instance only through a local Unix socket (mode 0600), never over
the network.

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
| `ergosum/v1/event` | instance key | position of a journal event, `[origin, seq, kind, hash]` (ADR 0003); a bare signature, not an envelope |

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
  "key": "<base64 DER SubjectPublicKeyInfo>",
  "to": "SHA256:<fingerprint of the authority instance>"
}
```

- `identity` is a lower-case FQDN.
- `request_id` is new for every request to an instance and never reused.
- `addresses` are the machine's underlay addresses (at most 16). The
  authority uses them only to pick the destination of a `net` check, and only
  addresses inside the bound prefix.
- `timestamp` must lie within the authority's clock-skew window (default
  ±2 minutes).
- `to` is the key fingerprint of the instance the request is addressed to,
  the one the daemon pins for that URL. A request is meant for exactly one
  instance: the daemon has it in flight to that instance only, and would
  answer a callback from any other with "no open request". Without `to`, an
  instance holding a request could pass it on to another one and make the
  real machine sign evidence against itself.

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
  "timestamp": "2026-10-27T20:00:01Z",
  "started": "2026-10-27T08:12:40Z"
}
```

`status` is `confirmed` if the daemon has a request with this ID in flight
to the calling instance (the TLS client key); `ended` if this daemon
process made that request to the calling instance but has given up on it,
within the last 10 minutes (timeout, or it moved on to the next instance);
otherwise `no_open_request`. `started` is when the daemon process started.
The response repeats request ID, nonce, target and authority; the authority
checks all four and the signature against the bound key.

A signed `no_open_request` from the bound key is proof that the key is used
by someone else, if the daemon process already ran when the request was
made (`started` not after the request's `timestamp`, both from the
machine's clock); the authority keeps it as evidence (ADR 0003). From a
process started later it proves nothing: the request may have come from
the process before it. `ended` proves nothing either. In both cases the
authority discards the request like one whose requester went away.

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
| 429 | `rate_limited` | the identity has a request in flight at this instance, or asked too often |
| 503 | `unavailable` | instance sealed or journal unavailable |

`denied` deliberately does not say which check failed, so that a prober
learns nothing. The daemon tries the next authority on any error.

### Request IDs, replays and restarts

A disk image or snapshot of a machine carries its key. A request ID that
the real machine confirms must therefore be worthless to the copy:

- The daemon creates a new request ID for every request to an instance and
  never reuses it. It keeps its requests in flight in memory only, each with
  the key of the instance it went to; nothing about requests is on disk.
- It confirms a callback only for a request in flight to the calling
  instance. For 10 minutes after it gave a request up it answers that
  instance `ended`; at every other instance, and later, the answer is
  `no_open_request`.
- An instance processes a request ID at most once per identity. A repeat
  within 15 minutes (and at least twice the clock-skew window) is refused
  as `replay`, without a callback; this outlasts `ended`, so that nobody can
  replay an ended ID to get `ended` instead of a proof. Later, the real
  machine no longer confirms it.
- If the requester's connection closes before the outcome is decided
  (daemon timeout, crash, restart), the instance cancels its callbacks and
  discards the request: no token, no observation.

A crash, restart or timeout therefore never turns into a `key_duplicate`.
Usually the instance notices that the requester left and drops the request.
If it does not in time (a slow callback, a connection broken on one side
only), the daemon answers `ended`; a daemon restarted meanwhile answers
`no_open_request` with a `started` after the request, which proves nothing.
A second key holder gains from this only a request without proof right
after the real machine restarted, never a token.

### Authority procedure

1. Verify the envelope, the timestamp and the identity syntax.
2. Look up the projected binding. No active binding: `unknown_identity`.
3. Fingerprint of `key` differs from the binding, or the signature does not
   verify: `foreign_key`. No callback is made.
4. `to` names another instance: `misdirected`. No callback is made. The
   request verified against the bound key, so whoever brought it here had it
   from the machine: another instance or a relay.
5. The identity has another request in flight here, or used up its rate
   (10 requests, then one per minute): `rate_limited`. No callback is made,
   nothing is journaled. Only a holder of the bound key gets this far, so
   a copy of it can keep its own identity from a token here, but no other.
6. Request ID already processed for this identity: `replay`. No callback is
   made.
7. Plan one callback per bound check; targets and ports come from the
   binding. A `net` check whose prefix is not inside a network attached to
   this instance: answer `not_responsible` before any callback.
8. Run the callbacks (in parallel, each with a timeout, default 5 s). Each
   uses a fresh nonce. For `net`, try up to four reported addresses inside
   the prefix.
9. Requester gone, or any callback answered `ended` or `no_open_request`
   from a daemon started after the request: discard. Otherwise any
   `no_open_request`:
   `key_duplicate`; any callback that is unreachable, answers with another
   key or answers invalidly: `wrong_location`. All confirmed: issue the
   token.

### Reachability rules

- `tailnet` callbacks must reach an overlay address.
- `ip` and `net` callbacks must neither reach an overlay address nor leave
  from one, so that an exit node or overlay route cannot carry an underlay
  check. Source address and interface per check kind are configurable.
- A `net` check runs only on an instance attached to that network.

### Authority list

An authority may serve `GET /v1/authorities` on its token listener: every
instance of its trust domain with its key fingerprint and one to eight
URLs (`https://HOST:PORT`, `HOST` an address or a DNS name) in order of
preference, and a serial from 1 to 2^53−1. Without a list it answers 404
`no_list`.

```json
{"v": 1, "trust_domain": "example.com", "serial": 3, "authorities": [
  {"key": "SHA256:...", "urls": ["https://100.64.0.10:7432", "https://192.0.2.10:7432"]}]}
```

- The operator keeps the same file (`authorities_file`) on every instance
  and raises the serial with each change. An instance reads the file again
  when it changes; a file that turns invalid leaves the last good list in
  place. An instance does not start with a file that does not name it.
- A daemon's configuration names at least one authority, its anchor. After
  each token the daemon asks the issuing instance for its list and takes it
  if it names that instance, is for the token's trust domain, and either
  has a higher serial than the list in use or comes from an instance that
  the configuration names and the list in use does not (a new trust domain,
  or new instances after a restart). The daemon keeps the list in its state
  directory and tries its instances in list order, then the configured ones
  it does not name. Callbacks are accepted only from these instances.
- The list is as trustworthy as the pinned connection to an instance the
  daemon already trusts. A wrong list can keep a daemon from reaching an
  authority, but cannot make it accept a token or let another instance use
  its requests: Vault checks tokens against the trust domain's keys, and a
  request names its target instance (`to`).
- The daemon tries a URL only if it can reach it from its own addresses:
  an overlay address needs an overlay address on the machine, an IPv4
  address an IPv4 address, another IPv6 address an IPv6 address outside the
  overlay; names and loopback addresses always. If none fits, it tries all.
  Each connection attempt is bounded (5 s). It moves to the next URL only
  while the request has not been written (connection or TLS handshake
  failed), so that one request never reaches an instance twice.
- The administrator's tool asks every configured authority for its list,
  insists that those that answer agree on serial and content, and adds the
  listed instances it does not know.

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
  with a signed proof of key duplication. A request ID taken from a disk
  image gets refused as `replay` or ends in the same proof.
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
- A daemon restart costs the request in flight; the daemon simply starts a
  new one.
- The replay check is per instance. Across instances the in-flight rule
  carries the protection alone.
- Daemon configuration must list every authority's fingerprint.
