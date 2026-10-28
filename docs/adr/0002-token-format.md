# ADR 0002: Identity token format

- Status: proposed
- Date: 2026-10-27
- Related: [ADR 0001](0001-protocol.md)

## Context and problem statement

The authority hands out a short-lived token that proves "this is machine X".
The token is consumed by HashiCorp Vault or OpenBao through the built-in JWT
auth method; Vault Agent on the machine reads it from a file and logs in.
The format must be verifiable by that stock auth method without plugins, and
it should not lock the namespace into ergosum if SPIFFE/SPIRE is adopted
later.

## Decision drivers

- Verifiable by Vault's and OpenBao's JWT auth with static public keys
  (`jwt_validation_pubkeys`), no plugin, no JWKS fetch from Vault to the
  authority.
- One audience only: a token must not be replayable to another service.
- Identity only, no roles or permissions.
- SPIFFE-compatible identifiers.
- Short lifetime, because the token is a bearer token in a file.

## Considered options

1. **JWT-SVID layout, ES256** (chosen).
2. **X.509-SVID / client certificates.** Needs a PKI mount, revocation and
   cert auth; mTLS certificates can still be derived through Vault later.
3. **PASETO or a custom token.** Not supported by Vault's JWT auth.
4. **ES256K or EdDSA.** Not supported by Vault's and OpenBao's JWT auth
   (ES256K) or by hardware-backed keys commonly available (secp256k1).

## Decision outcome

Chosen option 1: a JWT (RFC 7519), compact serialization, signed with ES256
(ECDSA P-256, SHA-256), following the SPIFFE JWT-SVID layout.

### Header

```json
{"alg": "ES256", "kid": "<RFC 7638 thumbprint of the instance key>", "typ": "JWT"}
```

Each authority instance signs with its own key; `kid` names it.

### Claims

| Claim | Value |
| --- | --- |
| `iss` | issuer name shared by all instances, e.g. `https://ergosum.example.com` |
| `sub` | SPIFFE ID `spiffe://<trust domain>/host/<identity>` |
| `aud` | `["vault"]` (configurable, one value) |
| `host` | the identity (FQDN), for Vault policy templating |
| `iat`, `nbf` | issuance time |
| `exp` | `iat` + lifetime, default 30 minutes |
| `jti` | random 128-bit ID, base64url |
| `checks` | sorted list of the check kinds that passed, e.g. `["ip","key","tailnet"]` |

`checks` always contains `key`. The individual callback targets and their
outcomes go to the audit log and the journal, not into the token.

### Lifetime and renewal

- Default lifetime 30 minutes. The daemon renews from half the lifetime on,
  spread by ±10 % of the lifetime, with exponential backoff and full jitter on
  failure.
- Every renewal is a full request with all callbacks. A token never renews
  itself; otherwise a copied token could be extended indefinitely.

### Publication of the verification keys

- `GET /v1/keys` returns a JWK Set, `GET /v1/keys.pem` the PEM public key, on
  the ops listener (also while sealed) and on the API listener.
- `ergosum keygen` prints `kid`, fingerprint and PEM when a key is created.
- Vault is configured with the PEM keys of all instances
  (`jwt_validation_pubkeys`) and `bound_issuer`. A role binds `aud`, maps
  `sub` as user claim and `host` into alias metadata.
- Key rotation: add the new public key to Vault, switch the instance, remove
  the old key.

### Token file

The daemon writes the token atomically (temporary file, `fsync`, rename) with
mode 0640 and the group configured for the token reader (default
`ergosum-token`).

## Consequences

**Good**

- Works with stock Vault and OpenBao JWT auth; no code in Vault.
- `sub` is a valid SPIFFE ID, so a later move to SPIRE keeps the namespace.
- One audience keeps a compromised consumer from replaying the token
  elsewhere; other consumers receive credentials derived through Vault.

**Bad**

- A bearer token: whoever copies the file can use it until it expires
  (at most the lifetime) and keep the Vault session it opened.
- Clock skew between machine, authority and Vault eats into the lifetime;
  the daemon exports its estimated skew as a metric.
- Adding another audience later is a format change and needs its own
  decision.
