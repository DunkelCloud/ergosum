# Architecture decision records

Format: [MADR](https://adr.github.io/madr/).

A record stays `proposed` until the change it describes has been tried in
operation; until then it may still be edited. Once tried, it becomes
`accepted`, and from then on it is append-only: a change is a new record
that supersedes the old one.

| No. | Title | Status |
| --- | --- | --- |
| [0001](0001-protocol.md) | Request and callback protocol | proposed |
| [0002](0002-token-format.md) | Identity token format | proposed |
| [0003](0003-journal-format-and-replication.md) | Binding journal format and replication | proposed |
| [0004](0004-releasing-secrets-without-vault.md) | Releasing secrets without Vault | proposed |
| [0005](0005-unsealing-through-the-other-instances.md) | Unsealing an instance through the other instances | proposed |
