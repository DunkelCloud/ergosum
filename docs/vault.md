# Using the token with Vault or OpenBao

HashiCorp Vault and OpenBao accept the ergosum token as a login through
their built-in JWT auth method. Vault Agent on the machine logs in with the
token file and renders the machine's secrets, for example the settings of
its database client. The machine then holds no long-lived Vault credential
at all.

This page shows the setup in three parts: Vault itself (once), the secrets
of each machine, and Vault Agent on each machine.

## Setting up Vault

[`deploy/vault/machine-auth.sh`](../deploy/vault/machine-auth.sh) sets up
everything Vault needs. Run it from a workstation with the `vault` CLI
(for OpenBao, `bao` and `VAULT=bao`), `jq` and `diff`, logged in with a
token that may manage auth methods and policies:

```sh
export VAULT_ADDR=https://vault.example.com:8200 VAULT_TOKEN=...
deploy/vault/machine-auth.sh plan -issuer https://ergosum.example.com \
  -trust-domain example.com -key authority-a.pem -key authority-b.pem \
  -identity host1.example.com -identity host2.example.com
```

| Option | Value |
| --- | --- |
| `-issuer` | `issuer` from the authorities' `serve.yaml` |
| `-trust-domain` | `trust_domain` from `serve.yaml` |
| `-key FILE` | the public key of each authority instance, one option per instance: the PEM block that `ergosum keygen` printed, saved as a file, or fetched on the authority with `curl -s http://127.0.0.1:7434/v1/keys.pem` |
| `-identity NAME` | each machine that may log in, one option per machine; or `-all-identities` for every machine of the trust domain |

`plan` shows what would change. `apply` with the same options shows it
again, asks, and writes only what differs:

```sh
deploy/vault/machine-auth.sh apply -issuer https://ergosum.example.com \
  -trust-domain example.com -key authority-a.pem -key authority-b.pem \
  -identity host1.example.com -identity host2.example.com
```

Every run states the whole set: a key or an identity left out is removed.
So when you add a machine or an authority instance, run `apply` again with
the complete list. With `-all-identities`, new machines need no change in
Vault.

The way back removes everything the script created:

```sh
deploy/vault/machine-auth.sh rollback
```

It disables the auth mount, which revokes every Vault token issued through
it, and deletes the policy. It deletes neither the identity entities that
logins created nor the secrets.

## Storing a machine's secrets

Each machine reads the secrets below its own name in the KV version 2
mount `secret`: `secret/host/<identity>/`, with one subpath per
application. For the example, a PostgreSQL client:

| Path | Keys |
| --- | --- |
| `secret/host/<identity>/db/config` | `host` and `database`, such as `db1.example.com` and `app` |
| `secret/host/<identity>/db/credentials` | `user`, `password` |

```sh
vault kv put secret/host/host1.example.com/db/config host=db1.example.com database=app
vault kv put secret/host/host1.example.com/db/credentials user=app password=...
```

A machine can read everything below `secret/host/<identity>/`. Keep
credentials it must not hold, such as the database administrator's,
outside that tree.

## Vault Agent on the machine

1. Install Vault Agent (the `vault` binary, as `/usr/bin/vault`) from
   HashiCorp, or `bao` for OpenBao, and create its user `vault` if the
   package did not.
2. The agent's user must be in the group `ergosum-token` to read the token.
   The systemd unit below adds the group on its own
   (`SupplementaryGroups=`); with OpenRC, run `addgroup vault
   ergosum-token`, on a Mac `sudo dseditgroup -o edit -a vault -t user
   ergosum-token`.
3. Take [`examples/vault-agent/agent.hcl`](../examples/vault-agent/agent.hcl)
   as `/etc/vault-agent/agent.hcl`, and set your Vault address in it. It
   logs in at `auth/machine` with role `host` and the token file
   `/run/ergosum/token`; on a Mac, change `path` to
   `/var/db/ergosum/token`.
4. Take [`examples/vault-agent/db.env.ctmpl`](../examples/vault-agent/db.env.ctmpl)
   as `/etc/vault-agent/db.env.ctmpl`. It renders the database settings
   to `/run/vault-agent/db.env` (mode 0600, in memory only). It takes the
   machine's identity from the Vault login, so the same file works on
   every machine.
5. Install the service: [`deploy/systemd/vault-agent.service`](../deploy/systemd/vault-agent.service)
   or [`deploy/openrc/vault-agent`](../deploy/openrc/vault-agent), and start
   it.

A job on the machine then runs:

```sh
. /run/vault-agent/db.env && psql ...
```

## Advanced

### What the script creates

`machine-auth.sh` owns three objects and touches nothing else. An auth
mount or a policy of the same name that it did not create stops it.

| Object | Content |
| --- | --- |
| auth mount `machine` | JWT auth method; `jwt_validation_pubkeys` holds the public key of every authority instance, `bound_issuer` the shared `issuer` |
| role `host` | `bound_audiences` `vault`, `user_claim` `sub`, `bound_claims` on `sub` with the named identities (`-identity`) or every identity of the trust domain (`-all-identities`), the `host` claim mapped into the alias metadata, Vault token TTL and max TTL 1 h, policy `host-secrets` |
| policy `host-secrets` | read on `secret/data/host/<host>/*`, `<host>` taken from the alias metadata of the login |

Other names: `-path`, `-role`, `-policy`, `-audience`, `-ttl`, `-kv`
(the KV mount) and `-prefix` (the path below it). With another mount or
prefix, change the paths in the template to match; the policy grants
nothing else. `machine-auth.sh -h` lists all options.

### Token lifetimes

Vault accepts an ergosum token until its expiry plus 60 seconds of clock
skew; the role sets `expiration_leeway` to -1 so that nothing is added on
top. The Vault token lives for an hour and cannot be renewed beyond that;
then Vault Agent logs in again with the token that is in the file at that
time. `agent.hcl` sets `remove_jwt_after_reading = false`: the daemon
replaces the file before it expires, and the agent reads it again for every
login.

### Secrets that several machines share

Secrets that several machines share, such as the credentials of a service
they all call, belong in one place outside the machine trees, for example
`secret/app/<application>/`, rather than in a copy per machine. Grant them
through a Vault identity group: a policy that reads the shared path, and the
machines' entities as members. A machine's token carries the group's
policies in addition to `host-secrets`. An entity appears with the first
login; to add a machine to a group before that, create its entity and an
alias named after its SPIFFE ID (`spiffe://<trust domain>/host/<identity>`)
on the `machine` mount, and the first login uses it.

### Retiring a machine in Vault

When a machine is decommissioned, disable its Vault entity, whose alias is
`spiffe://<trust domain>/host/<identity>` on the `auth/machine` mount, so
that Vault tokens it still holds stop working; `ergosum revoke` prints the
commands. If the role names identities, run `apply` again without it.

### Changing an authority instance's key

Add the new public key with `apply` and both `-key` options **before** any
machine gets tokens from the new key, and remove the old one afterwards.
The full order is in [Changing an instance's
key](multiple-authorities.md#changing-an-instances-key).
