# Monitoring

ergosum reports its state in three ways: a **health check** on each
authority instance, **Prometheus metrics** from authorities and machines,
and an **audit log** of every request and change.

## Health check

Each authority instance answers on its ops listener (default
`127.0.0.1:7434`, plain HTTP):

```sh
curl -s http://127.0.0.1:7434/healthz
```

| Answer | Status | Meaning |
| --- | --- | --- |
| `ok` | 200 | the instance issues tokens and its journal maintenance works |
| `sealed` | 503 | the instance waits for `ergosum unseal` and issues nothing |
| `degraded: ...` | 200 | the instance issues tokens, but its journal maintenance keeps failing; the text names the step (`journal`, `checkpoint` or `compaction`), the error and since when |

An example of the last one: `degraded: journal maintenance failing since
2026-11-06T09:39:15Z: compaction: disk I/O error (6410)`. Degraded is
deliberately not 503, so that a liveness check does not restart an
instance that the restart would seal. Alert on
`machine_identity_journal_maintenance_failing` instead.

## What to alert on

[`deploy/prometheus/ergosum-alerts.yml`](../deploy/prometheus/ergosum-alerts.yml)
holds proposed alerting rules. Adjust thresholds and labels before you
activate them. The most important ones:

| Alert | What happened | What to do |
| --- | --- | --- |
| `ErgosumKeyDuplicate` (critical) | A machine's key exists twice: the real machine answered a callback with "I made no such request" (`key_duplicate`), someone reused one of its request IDs (`replay`, typically a copy from a disk image), or a request the machine addressed to another instance was passed on (`misdirected`). | Treat it as a security incident. The authority's audit log names the identity and the evidence. Give the machine a [new key](administration.md#everyday-changes) and find the copy. |
| `ErgosumAuthoritySealed` | An instance has been sealed for 15 minutes and issues nothing. | Run `ergosum unseal` on that host. |
| `ErgosumJournalEventRejected` | An instance received a journal event that does not verify. Replication from that peer stops there. | Usually the registries differ between the instances; otherwise someone forged an event. |
| `ErgosumJournalEquivocation` | An instance signed two contradicting events. The contradicting event is skipped; replication goes on. | Take the named instance out of service and investigate. |
| `ErgosumJournalOutboxStuck`, `ErgosumJournalCoverageDiverges` | Instances do not catch up with each other. | Check the network between the instances (TCP 7435) and their logs. A peer added without a sync can stay behind this way for good. |
| `ErgosumJournalCheckpointStale`, `ErgosumJournalMaintenanceFailing` | Checkpoints or compaction fail; the journal keeps growing. | The authority's log names the error; often the disk. |
| `ErgosumJournalEventsSkipped` | Another instance's records exceed `origin_quota_mib`. | See [Replication settings](multiple-authorities.md#replication-settings). |
| `ErgosumSecretPinsBelowThreshold` | A machine cannot reach enough instances for one of its [secrets](secrets.md). | Fix the instances; do not lower the threshold. |

It is also worth alerting when a machine's token is about to run out,
which means that it has stopped getting new ones, for example:

```text
machine_identity_token_expiry_timestamp_seconds - time() < 600
```

## Authority metrics

`/metrics` on the ops listener.

| Metric | Meaning |
| --- | --- |
| `machine_identity_requests_total{result}` | token requests by result: `issued`, `key_duplicate`, `wrong_location`, `replay`, `misdirected`, `rate_limited`, `foreign_key`, `unknown_identity` |
| `machine_identity_exchanges_total{result}` | exchange requests for [secrets without Vault](secrets.md), with the same results; `issued`: the checks passed and the instance answered |
| `machine_identity_authority_sealed` | 1 while sealed |
| `machine_identity_build_info{version,commit}` | 1; version and commit of the running binary |
| `machine_identity_binding_events_total{outcome}` | binding changes: `accepted`, `rejected` |
| `machine_identity_journal_outbox_events{peer}` | events a peer has not acknowledged |
| `machine_identity_journal_outbox_oldest_age_seconds{peer}` | age of the oldest of them; 0 if none |
| `machine_identity_journal_rejected_total{peer}` | events from a peer that were rejected on arrival |
| `machine_identity_journal_equivocations_total{origin}` | events skipped because their origin signed a contradicting event; take that instance out of service |
| `machine_identity_journal_skipped_total{origin}` | observations and checkpoints skipped over the quota of their origin, or too far above its coverage; check that instance |
| `machine_identity_journal_origin_bytes{origin}` | what the observations and checkpoints of another origin take here, against `origin_quota_mib` |
| `machine_identity_journal_coverage{origin}` | sequence number up to which every event of an origin is here |
| `machine_identity_journal_compaction_frontier{origin}` | sequence number up to which events of an origin may be deleted |
| `machine_identity_journal_checkpoint_age_seconds` | age of the latest own checkpoint; -1 before the first |
| `machine_identity_journal_compacted_events_total` | events deleted by compaction |
| `machine_identity_journal_maintenance_failing` | 1 while the latest checkpoint or compaction failed; `/healthz` then answers degraded |

What the request results mean:

- `issued`: the token was issued.
- `key_duplicate`: proof that a machine key exists twice; critical.
- `replay`: someone with the machine key reused a request ID the machine
  had sent, typically a copy from a disk image; treat it like
  `key_duplicate`.
- `misdirected`: a request the machine addressed to another instance
  arrived here: that instance, or whoever relayed the request, passed it
  on.
- `wrong_location`: a callback failed; a warning. Often a firewall, or a
  machine that moved.
- `rate_limited`: more than 10 requests of one identity and then more than
  one per minute, or a request while another of the same identity is in
  flight. Many of them usually come from a copy of the machine key,
  together with `key_duplicate`.
- `foreign_key`: the request does not verify against the bound key.
- `unknown_identity`: there is no binding for the name, or it is revoked.

## Machine metrics

The daemon writes its metrics to a file for the node_exporter textfile
collector when `metrics_file` is set in `ergosumd.yaml`, for example
`/var/lib/node_exporter/textfile_collector/ergosum.prom`. Under systemd,
that directory needs `ReadWritePaths=` in the unit (see the comment in
`ergosumd.service`).

| Metric | Meaning |
| --- | --- |
| `machine_identity_token_expiry_timestamp_seconds` | expiry of the current token |
| `machine_identity_last_success_timestamp_seconds` | last successful request |
| `machine_identity_last_error_timestamp_seconds` | last failed request |
| `machine_identity_clock_skew_seconds` | authority clock minus local clock, estimated from request rounds of at most 10 s |
| `machine_identity_callbacks_total{status}` | callbacks answered: `confirmed`, `ended` (a late callback for a request this daemon gave up), `no_open_request` (the key is used elsewhere) |
| `machine_identity_key_change_pending` | 1 while a new key waits for its binding |
| `machine_identity_build_info{version,commit}` | 1; version and commit of the running binary |
| `machine_identity_authorities_serial` | serial of the authority list in use; 0 while the daemon knows only its configuration |
| `machine_identity_secret_threshold{name}` | threshold of each secret the daemon holds open |
| `machine_identity_secret_pins{name}` | instances of that secret that answered its last refresh |
| `machine_identity_secret_reshare_pending{name}` | 1 while a re-split part A waits for the next `get` to write it |

## Audit log

The authority writes an audit entry as a JSON log line with
`"log_type":"audit"` to stdout, ready for any log pipeline:

- one per token or exchange request: result, identity, request ID,
  presented key, the outcome of every check, token ID;
- one per binding change.

Evidence of a copied key (`key_duplicate`, `replay`, `misdirected`) is
logged at level `error` with an `alert` field.

Requests that do not verify against a bound key (`foreign_key`,
`unknown_identity`, and timestamps outside the accepted window) and
rejected binding changes can come from anyone on the network. They are
never stored in the journal, and their log lines are limited to 60 per
minute in total; the metrics count all of them.

To read the log by eye:

```sh
journalctl -u ergosum -o cat | grep '"log_type":"audit"'
```
