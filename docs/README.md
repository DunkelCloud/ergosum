# ergosum documentation

New to ergosum? Read [How ergosum works](concepts.md) for the ideas and the
vocabulary, then follow [Getting started](getting-started.md) for a first
installation.

## Guides

| Page | For | What it covers |
| --- | --- | --- |
| [How ergosum works](concepts.md) | everyone | the parts, what happens when a machine gets a token, checks, ports, where the installation values come from, glossary |
| [Getting started](getting-started.md) | whoever sets ergosum up | a first installation step by step: one authority, one administrator, one machine |
| [Machines](machines.md) | machine administrators | `install.sh` and its options, the Mac, checking, troubleshooting, updating, removing, backups |
| [Administration](administration.md) | ergosum administrators | the admin tool, approving machines, choosing checks, everyday changes, decommissioning |
| [Running an authority](authority.md) | authority operators | installing, configuration, signing key and sealing, network, containers, updating |
| [Several authority instances](multiple-authorities.md) | authority operators | authority list, replication, adding and removing instances, key changes, journal maintenance |
| [Vault and OpenBao](vault.md) | Vault administrators | setting up Vault, storing machine secrets, Vault Agent |
| [Secrets without Vault](secrets.md) | machine administrators | sealing a secret such as a backup password with `ergosumd secret` |
| [Monitoring](monitoring.md) | operations | health check, alerts, metrics, audit log |
| [Releases](releasing.md) | everyone; maintainers | release contents, verifying downloads, making a release |

Every page starts with what most administrators need. Sections under
**Advanced** at the end of a page explain the details; you can skip them on
a first read.

## Reference

- Example configuration with comments: [`examples/`](../examples)
  ([authority](../examples/serve.yaml), [machine](../examples/ergosumd.yaml),
  [authority list](../examples/authorities.yaml),
  [Vault Agent](../examples/vault-agent))
- Service definitions for systemd, OpenRC and launchd, alert rules and the
  Vault setup script: [`deploy/`](../deploy)
- Every command explains its arguments with `-h`, such as `ergosum bind -h`
  or `ergosumd secret create -h`.
- [Architecture decision records](adr/): the protocol, the token format,
  the journal and replication, releasing secrets without Vault. They
  describe the design in depth and are written for developers and
  reviewers.
