# Secrets without Vault

Not every installation has Vault. `ergosumd secret` keeps a secret, such as
the password of a backup repository, on the machine in sealed form. It
opens only after the machine has passed the checks of its binding at
several authority instances, much like Tang and Clevis unlock a disk only
in the right network. A copy of the sealed secret elsewhere, in a stolen
backup for example, opens nothing.

It fits every tool that reads a password from a command, such as restic
(`--password-command`, `RESTIC_PASSWORD_COMMAND`) and borg
(`BORG_PASSCOMMAND`). The design is in [ADR
0004](adr/0004-releasing-secrets-without-vault.md).

## How it works, briefly

`ergosumd secret create` splits the secret into *shares*. Each share is
tied to one authority instance; the sealed rest, *part A*, is stored on the
machine as `/etc/ergosum/secrets/NAME`. To open the secret, the daemon has
to collect shares from at least a **threshold** of instances, and each
instance hands out its share only after it has checked the machine, exactly
as for a token.

Choose the threshold accordingly:

- **2 or more** (recommended). Then you need at least that many authority
  instances with an exchange key, and a single compromised instance cannot
  open anything.
- **1** works with a single instance, but is weak: that instance's
  exchange key and a copy of part A open the secret without any check.

## Preparing the authorities

Each instance that should take part needs an **exchange key**, a second
key next to its signing key:

```sh
ergosum keygen -exchange -out /etc/ergosum/exchange.key            # plain key file
ergosum keygen -exchange -out /etc/ergosum/exchange.key -encrypt   # with the signing key's passphrase
chgrp ergosum-authority /etc/ergosum/exchange.key && chmod 0640 /etc/ergosum/exchange.key
```

Add it to `serve.yaml` and restart (and unseal) the instance:

```yaml
exchange_key_file: /etc/ergosum/exchange.key
```

- **Never back up the exchange key.** The machines' sealed secrets lie in
  their backups; a copy of the exchange key next to one opens it without
  any check.
- Losing or replacing it takes the instance out of every secret that uses
  it; the machines move those secrets to the remaining instances (see
  below).
- An encrypted exchange key opens at `ergosum unseal` with the signing
  key's passphrase; if it does not open, the instance stays sealed. An
  encrypted exchange key next to a plain signing key is refused.

## Creating and using a secret

On the machine, as root. The daemon must be running, and the machine's
binding must be recorded.

```sh
# The secret is read from stdin; -recovery is optional, see below
printf '%s\n' "$RESTIC_PASSWORD" | ergosumd secret create restic -threshold 2 \
  -recovery 'age1...' -recovery 'ssh-ed25519 AAAA... admin@example.com'

# Show what was created
ergosumd secret info restic

# Use it
RESTIC_PASSWORD_COMMAND='ergosumd secret get restic' restic snapshots
```

`create` fails if fewer than the threshold of instances answer, and names
those that did not and why. It never overwrites an existing secret; to
change a secret, create a new one under another name, or delete the old
file first.

`get` prints the secret and nothing else, or prints nothing and exits with
code 1 if it cannot open it.

### The way back: recovery recipients

If all authorities are gone, a secret can still be opened with a
**recovery** key. `-recovery` takes an [age](https://age-encryption.org)
recipient (`age1...`) or an `ssh-ed25519` public key, once per
recipient. Part A then
contains a copy of the secret encrypted to these recipients, which you open
with the standard `age` tool, without ergosum: copy the `recovery` member
of part A into a file and run `age -d -i KEY FILE`. Keep the recovery
private keys offline.

## Monitoring

Alert when fewer instances answer for a secret than its threshold needs:
the metric `machine_identity_secret_pins` below
`machine_identity_secret_threshold`. The rule
`ErgosumSecretPinsBelowThreshold` in
[`deploy/prometheus/ergosum-alerts.yml`](../deploy/prometheus/ergosum-alerts.yml)
does that. Fix the instances; do not lower the threshold.

## Limits

- **No rotation.** A changed secret needs a new part A. Old copies of part
  A open the old secret as long as the exchange keys of their instances
  exist.
- **Root on the machine** can read part A and use the daemon's socket, so
  it can open the secret, as the machine itself can.
- **Threshold 1** is weak (see above).

## Advanced

### Details of the commands

- `create` uses every instance of the authority list that hands out a
  release key for the machine (at most 16), and fails with fewer than the
  threshold. It writes part A to `/etc/ergosum/secrets/NAME` (or `-file`),
  mode 0600. It removes one trailing newline from stdin; `-raw` keeps it.
- With `-file`, part A lies at that path; a relative path is taken from the
  working directory. `get` and `info` look for NAME only in
  `/etc/ergosum/secrets` and need the same `-file`; `create` prints it as an
  absolute path, the form a password command needs.
- `get` writes the secret to stdout as stored, without a newline. On any
  failure stdout stays empty and the exit code is 1.
- `info` shows name, identity, threshold, the instances and whether a
  recovery copy exists; it needs no daemon.

### Who may open a secret

Whoever may read part A may open the secret: the command reads the file
with the caller's rights and hands it to the daemon over its socket
(`secret_socket`, mode 0600; `secret_socket_group` opens it to one group,
and the daemon's user must be a member of that group). The daemon logs
every request with the caller's UID. Every opened secret costs requests out
of the identity's rate budget at the authorities.

### What the daemon keeps in memory

The daemon holds an opened secret in memory and answers from there while it
holds a valid token and no instance denied the last refresh. After each
token round it refreshes every held secret at its instances, one request
per instance. A revoked binding stops the secret at the next round; an
outage of the authorities does not, while the token lasts. After a restart
of the daemon, the first `get` needs the threshold of instances again.

### When the authority list changes

When instances are added or removed, the daemon re-splits held secrets: it
drops instances no longer listed and adds listed ones that hand out a
release key, but only if at least the threshold of the current instances
serve the same list, and never below the threshold. The next `get` replaces
part A atomically with the same owner and mode and says so on stderr; if it
cannot write the file, the re-split stays pending
(`machine_identity_secret_reshare_pending`).

### On the authority

Exchange requests run the same procedure as token requests (checks, rate
limit shared with token requests, replay protection, evidence of
failures), but issue no token: a successful exchange writes nothing to the
journal, only an audit line. Without an exchange key, `POST /v1/exchange`
answers 404 `no_exchange`, and machines do not use the instance for
secrets.
