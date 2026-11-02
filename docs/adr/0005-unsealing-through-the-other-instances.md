# ADR 0005: Unsealing an instance through the other instances

- Status: proposed
- Date: 2026-11-02
- Related: [ADR 0001](0001-protocol.md), [ADR 0004](0004-releasing-secrets-without-vault.md)

## Context and problem statement

An instance whose keys are encrypted starts sealed after every start and
issues nothing until an operator runs `ergosum unseal` on its host. Since
ADR 0004 this is no longer a choice for every instance: the exchange key
must never lie in a backup next to the machines' part A, and an instance
whose disk is backed up as a whole, as virtual machines usually are, can
keep it out of its backups only encrypted. One passphrase opens both keys.

Every restart of such an instance then waits for an operator: a host
reboot, a patch round, a power cut. Two instances in one site that release
a consumer's secret with a threshold of 1 of 2 are sealed together after a
site-wide restart, and the consumer stays without its secret until someone
unseals.

This ADR lets an instance unseal itself through the other instances, with
the means of ADR 0004, and keeps the manual unseal as the way back.

## Decision drivers

- No new protocol and no new format: the exchange and part A of ADR 0004,
  unchanged.
- An image of the instance (backup, snapshot, copy) opens nothing without
  passing checks at other instances; no weaker than what ADR 0004 accepts
  for every machine.
- An instance never takes part in releasing its own passphrase.
- Rolling restarts need no operator. After a restart of every instance that
  can release an instance's passphrase, one manual unseal brings the others
  back.
- The passphrase stays valid: an operator can always unseal by hand.

## Considered options

1. **The passphrase as a secret of ADR 0004, sealed to the other
   instances and opened by a daemon on the instance's host** (chosen).
2. **Manual unseal only.** The strongest against someone inside the bound
   network who also holds the backups; every restart waits for an operator.
3. **Plain keys, and the instance's host out of every backup.** No unseal at
   all; a lost host is rebuilt with a new signing key, which changes Vault
   and the authority lists. It also relies on every backup and snapshot of
   the host staying switched off.
4. **Shares of the passphrase kept by the other instances**, in their
   journal or configuration: state per instance, a write path, and secrets
   at every instance, rejected in ADR 0004 for machines for the same
   reasons.
5. **A KMS or Vault auto-unseal.** Depends on the system ADR 0004 avoids, and
   Vault's own unseal could in turn depend on ergosum.
6. **A passphrase sealed to a TPM.** Binds to one virtual machine's vTPM
   state, not to a place; a copy with that state opens it.

## Decision outcome

Chosen option 1.

### Setup

- The instance's host runs `ergosumd` with an identity of its own, bound
  like any machine, with the checks that fit its place: a net check for its
  segment, an overlay or ip check.
- `ergosumd.yaml` on that host names the local instance:

  ```yaml
  local_authority: "SHA256:<fingerprint of the instance on this host>"
  ```

  The daemon never pins that instance, neither when it creates a secret nor
  when it re-splits one. Its release would need it unsealed already, and
  its exchange key, encrypted under the passphrase, would close a circle.
- The passphrase becomes a secret of the host, with part A in
  `/etc/ergosum/secrets/unseal`, mode 0600, owned by root:

  ```sh
  ergosumd secret create unseal -threshold K -recovery RECIPIENT ...
  ```

- A start job runs after the instance and the daemon and repeats, with a
  backoff, until the instance is unsealed:

  ```sh
  ergosumd secret get unseal | ergosum unseal
  ```

  `ergosum unseal` reads the passphrase from stdin when it has no terminal.
  For an instance in a container the right side is
  `docker exec -i CONTAINER ergosum unseal`.

### Which instances count

As in ADR 0004, an instance is pinned only if it can run every check of the
host's binding: one that cannot run a net check answers `not_responsible`.
For a host in a site with a second instance and a net check in its binding,
that is the other instance of the site; a remote instance that reaches the
site only through the overlay does not count. An overlay check alone is
weak here: the overlay's node key lies in the host's backup too.

K follows from the instances that count. With one other instance in the
site, K is 1, and each instance of the site unseals the other. An instance
alone in its site has none that counts with a net check; it keeps the
manual unseal, or its host is bound with checks that remote instances can
run, such as an ip check for a public address.

### Order after a site-wide restart

The instances of a site that are restarted together are all sealed: none
can release the others' passphrases. Instances elsewhere keep issuing
tokens meanwhile. An operator unseals one of them by hand; the start jobs
of the others then open their passphrases there and unseal. With K above
1, as many are unsealed by hand as K requires.

### What lies where

- On the host, and so in its backups: the encrypted signing and exchange
  keys, part A of the passphrase, the daemon's identity key and the
  overlay's state. None of it opens anything without the checks of K other
  instances.
- The passphrase itself stays with the operators, and `-recovery` adds the
  operators' age recipients to part A.

### Security

- An image restored inside the bound network passes the checks, as ADR 0004
  states for every machine. It then gets the passphrase, with it the
  instance's exchange key, and with a copy of a consumer's part A that
  consumer's secret. Manual unseal (option 2) is stronger against someone
  who is inside the network and holds the backups; the choice is per
  instance.
- While the original host runs, a copy that asks is called back at the
  bound places too; where the original answers "no open request", the
  instance records a key duplicate and alerts.
- Revoking the host's binding stops its unseal at the instance's next start.
- After a `get`, the daemon holds the passphrase in memory (ADR 0004,
  releases per round). Root on the host reaches the unsealed keys in the
  instance's memory anyway.
- `machine_identity_authority_sealed` and its alert stay: a start job that
  does not get through shows as an instance that stays sealed.

### Changes

- `ergosumd.yaml`: `local_authority`, the fingerprint of the instance on
  the same host, left out of `secret create` and of re-splitting.
- `ergosum keygen -from FILE -encrypt -out FILE`: encrypts an existing
  signing key, so that an instance changes to encrypted keys without a new
  key and without changes to Vault or the authority lists.
- A start job for systemd and OpenRC, and the container variant in the
  operations documentation.

Nothing changes in the protocol, the token, the journal or part A.

## Consequences

**Good**

- Restarts, one instance at a time, need no operator, although the keys lie
  in backups only encrypted.
- No new protocol, format or key material; the manual unseal stays.
- The instances of one site cover each other.

**Bad**

- An image restored inside the bound network unseals itself: the limit of
  ADR 0004, now for the instance's keys too.
- A daemon, a binding and a start job on every instance's host.
- A restart of every instance that counts for another still needs one
  manual unseal.
- The passphrase stays in the daemon's memory.
