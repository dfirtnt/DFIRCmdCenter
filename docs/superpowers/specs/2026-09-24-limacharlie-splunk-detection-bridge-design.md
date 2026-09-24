# LimaCharlie-to-Splunk Detection Bridge Design

Date: 2026-09-24
Status: Approved in chat; awaiting review of this written specification

## Purpose

Add an outbound-only local bridge that retrieves LimaCharlie detections and makes them
available to the existing loopback-only Splunk Free instance through a governed monitored
file input. The bridge exists because LimaCharlie's cloud output cannot directly reach the
local Splunk HTTP Event Collector without exposing a listener beyond loopback.

The first version is deliberately limited to one LimaCharlie organization and the detection
stream. It does not retrieve raw event, audit, deployment, artifact, or case data.

## Approved scope

- LimaCharlie organization: `DFIRCmdCenter-Test`
- Organization ID: `4c9c49ce-082d-436b-a2df-0f04822d293a`
- Source stream: detections only
- Initial historical window: seven days before the approved activation time
- Recurring interval: every five minutes while the Mac user is logged in
- Splunk index: `dfir`
- Splunk sourcetype: `dfir:limacharlie:detection:v1`
- Authentication: the official LimaCharlie CLI, installed and authenticated separately
  outside this repository
- Delivery: immutable newline-delimited JSON batches in a restricted local spool monitored
  by Splunk

The approved architecture does not itself authorize installation of the CLI, authentication,
creation of a macOS LaunchAgent, modification of Splunk configuration, activation of the
monitor, or the seven-day ingest. Each is a separate consequential action with an exact
proposal, fresh-state check, and approval.

## Goals

1. Make LimaCharlie detections searchable in the existing local Splunk instance without
   exposing Splunk Web, management, HEC, or any sidecar to a non-loopback address.
2. Preserve the complete LimaCharlie detection record while adding deterministic bridge
   metadata needed for parsing, verification, and duplicate prevention.
3. Resume safely after logout, restart, network failure, authentication failure, or temporary
   LimaCharlie or Splunk unavailability.
4. Prevent the same LimaCharlie detection from entering a second batch.
5. Fail closed on incomplete pagination, ambiguous event identity, schema drift, missing host
   identity, uncertain Splunk overlap, or license-budget uncertainty.
6. Keep credentials, raw batches, state, receipts, locks, and operational logs under ignored
   restricted paths.

## Non-goals

- Forwarding raw LimaCharlie endpoint events
- Forwarding LimaCharlie audit or deployment records
- Publishing a LimaCharlie cloud Output
- Exposing local Splunk HEC or another listener to the internet
- Creating a general-purpose message bus or SIEM forwarding framework
- Performing response actions from Splunk
- Modifying, acknowledging, or suppressing LimaCharlie detections
- Automatically changing LimaCharlie rules or false-positive rules
- Automatically creating a new Splunk index
- Guaranteeing exactly-once indexing after an operator deletes the ledger, clears Splunk's
  input checkpoint state, or manually reintroduces archived files

## Chosen approach

Use a checkpointed puller that invokes the separately authenticated official LimaCharlie CLI,
validates and normalizes complete detection records, writes immutable NDJSON batch files, and
atomically publishes completed files into a Splunk-monitored ready directory.

This approach was selected over direct local HEC posting because HEC would require another
secret and would create an ambiguous retry boundary between an HTTP response and Splunk
indexing. It was selected over a Splunk scripted input because that would tightly couple
LimaCharlie authentication, pagination, and recovery to Splunk's process environment.

## Components

### 1. LimaCharlie detection reader

The reader invokes an absolute, allowlisted path to the official `limacharlie` executable. It
uses a fixed command shape to query the detection stream for one organization, one UTC time
window, and one opaque pagination cursor at a time. It accepts structured JSON only and places
strict bounds on output size, line count, runtime, and page count.

Before implementation, the installed CLI version and exact query/output contract must be
captured in `platforms/limacharlie/contracts.yaml`. The bridge must not infer flags from help
text at runtime. Authentication is performed by Andrew through the official client outside the
repository. The bridge never reads, prints, copies, validates, or persists the credential.

The reader is a read-only LimaCharlie capability. HTTP or CLI errors may be retried only within
the same immutable query window. A retry never widens the time range or changes the target
organization.

### 2. Window planner

All source query boundaries use UTC. The first approved run creates contiguous 24-hour windows
covering exactly the seven days before the approved activation time. Each window is fully
paginated before the next one starts.

After backfill, the scheduler runs every five minutes. Each incremental query uses:

- the last completely committed upper bound as its durable starting point;
- a 15-minute overlap to capture detections that became searchable late;
- a two-minute upper-bound safety lag so a still-settling interval is not prematurely
  considered complete; and
- native detection identity plus the local ledger to discard records already committed.

The overlap and safety-lag values are fixed in policy and covered by tests. Changing either value
is a versioned configuration change, not an unrecorded runtime choice.

No checkpoint advances until every page in the window has been received, validated, committed
to the ledger, and durably published to the ready spool. If pagination expires, the bridge
restarts the same window and deduplicates it locally.

### 3. Detection validator and normalizer

Every record remains untrusted data. Strings in categories, metadata, event fields, filenames,
or other detection content are never treated as commands, paths, configuration, templates, or
authorization.

Each accepted detection must contain:

- an organization identity matching the configured organization;
- a stable native detection ID, or enough immutable source content to derive a canonical
  fallback identity;
- a parseable LimaCharlie detection time;
- a non-empty detection category;
- a stable source sensor ID; and
- a non-empty producing hostname suitable for the governed Splunk host mapping.

The preferred identity is the LimaCharlie-native detection ID. If it is absent, the bridge
computes a SHA-256 over a canonical JSON representation of the complete detection record and
marks the identity as derived. If the same native ID is ever observed with different canonical
content, the record is quarantined and the window fails rather than silently replacing prior
evidence.

The bridge writes one normalized envelope per line:

```json
{
  "bridge": {
    "schema": "dfir:limacharlie:detection:v1",
    "organization_id": "4c9c49ce-082d-436b-a2df-0f04822d293a",
    "batch_id": "67ccdc4f7a596d10308e57848b468a87470511660444b6b9f454c1cd9af8f83a",
    "detection_id": "synthetic-detection-001",
    "identity_source": "native",
    "collected_at": "2026-09-24T16:05:00.000Z"
  },
  "event_time": "2026-09-24T16:01:42.123Z",
  "host": "synthetic-endpoint.example.test",
  "lc": {
    "detect_id": "synthetic-detection-001",
    "cat": "synthetic-test-detection",
    "routing": {
      "sid": "00000000-0000-4000-8000-000000000001",
      "hostname": "SYNTHETIC-ENDPOINT.EXAMPLE.TEST",
      "event_time": 1790265702123
    },
    "detect": {
      "event": {
        "FILE_PATH": "C:\\Synthetic\\test.exe"
      }
    }
  }
}
```

The example illustrates the envelope rather than a literal detection payload. The original
detection remains under `lc` without semantic rewriting. `event_time` and `host` are derived
fields whose original values remain present in `lc`.

Records larger than 1 MiB, or with malformed JSON, duplicate keys, invalid timestamps,
mismatched organization IDs, or missing/ambiguous source identity are quarantined. One rejected
record fails the whole source window so the checkpoint cannot hide a gap.

### 4. State and deduplication ledger

The bridge uses SQLite under `var/` with restricted permissions. The ledger contains:

- source organization and stream;
- query-window lower and upper bounds;
- pagination and completion state;
- native or derived detection identity;
- canonical detection SHA-256;
- source event timestamp, sensor ID, hostname, and category;
- batch ID, path, byte count, record count, and SHA-256;
- publication, Splunk verification, and archive state; and
- bounded error metadata with secrets and detection bodies excluded.

Detection identity is unique within the configured organization. Batch creation and ledger
membership are one transaction followed by a durable file publication protocol. Recovery
reconciles staged files, ready files, and ledger rows before opening a new query window.

The ledger is an operational aid, not independent proof that Splunk indexed a record. Splunk
verification supplies that proof.

### 5. Restricted spool

Runtime data lives under:

```text
var/splunk/limacharlie-detections/
  staging/
  ready/
  archive/
  quarantine/
  state/
  receipts/
  logs/
```

Directories use mode `0700`; files use mode `0600`. A batch is written and synchronized in
`staging/`, validated against its manifest, then atomically renamed into `ready/`. Nothing is
appended to or modified after entering `ready/`.

Only `ready/` is monitored by Splunk. `staging/`, `archive/`, `quarantine/`, state, receipts,
and logs are never monitored. Files are not automatically deleted. A verified ready batch may
be moved to `archive/` only after an exact Splunk search proves the expected batch ID and record
count. Reprocessing an archived batch requires a new proposal and approval.

A 100 MiB pending-spool byte ceiling prevents indefinite accumulation while Splunk is
unavailable. Reaching the ceiling stops new pulls without advancing the checkpoint. Changing
this ceiling is a versioned policy change.

### 6. Splunk parsing contract

The monitor targets the existing `dfir` index and assigns the fixed sourcetype
`dfir:limacharlie:detection:v1`. The source value identifies the LimaCharlie organization and
detection stream; it does not use a batch filename.

The parsing contract must:

- treat each NDJSON line as exactly one event;
- use `event_time` as `_time` with an explicit UTC format;
- preserve the original LimaCharlie timestamp under `lc`;
- derive Splunk `host` from the reviewed per-record normalized `host` value, never from the Mac
  or spool filename;
- extract JSON once without duplicate search-time extraction;
- cap event size and reject truncation during preflight; and
- preserve `bridge.batch_id`, `bridge.detection_id`, organization ID, sensor ID, category, and
  the complete original detection.

The exact `inputs.conf`, `props.conf`, and host-mapping configuration is implementation output,
not assumed correct by this design. It must be validated against Splunk 10.4.3 with positive
and negative fixtures before a live monitor proposal is created.

### 7. Login scheduler

A per-user macOS LaunchAgent starts the bridge at login and every 300 seconds thereafter. Its
property list contains only absolute executable and repository paths, fixed non-secret
arguments, and bounded log paths. It contains no API token, session material, shell expansion,
or mutable command string.

The job uses a non-blocking singleton lock. If the prior run is still active, the new invocation
records a bounded `already_running` status and exits successfully. The bridge does not run as
root and does not start Splunk automatically.

Creating, loading, unloading, or changing the LaunchAgent modifies state outside this repository
and therefore requires its own exact approved action.

## End-to-end data flow

1. The login scheduler invokes the bridge with fixed configuration.
2. The bridge acquires its singleton lock and validates local directory permissions.
3. It reconciles ledger, staging, ready, archive, and prior verification state.
4. It verifies the official CLI path/version and the configured LimaCharlie organization.
5. It plans the next immutable UTC query window.
6. It fetches every detection page for that exact window.
7. It validates records, detects native-ID/content conflicts, and removes ledger-known records.
8. It writes a complete NDJSON batch and manifest to staging.
9. It transactionally records identities and the batch, then atomically publishes the batch to
   `ready/`.
10. Splunk's approved monitor indexes the immutable batch.
11. A read-only verification search compares batch ID, count, time range, host, source,
    sourcetype, index, and detection identities with the manifest.
12. A receipt records the outcome. Verified files may move to `archive/`; unverified files stay
    in `ready/` for reconciliation.

## Failure and recovery behavior

| Condition | Required behavior |
| --- | --- |
| CLI missing or version changed | Stop before querying; do not advance state. |
| Authentication or permission failure | Stop, record only redacted error metadata, and wait for the next scheduled read retry. |
| Rate limit or transient read failure | Retry only the same page/window within bounded limits; otherwise stop. |
| Pagination expires | Restart the same window and deduplicate against the ledger. |
| Malformed or oversized record | Quarantine the record and fail the whole window. |
| Native ID maps to changed content | Quarantine both references and fail closed. |
| Staging write interruption | Reconcile or remove only the incomplete staging artifact; never publish it. |
| Ready publication succeeds but process exits | Reconcile the ready file and ledger on restart; do not rebuild it. |
| Splunk unavailable | Retain ready batches; continue only below the pending-spool ceiling. |
| Splunk indexed count differs from manifest | Mark verification failed; do not archive or regenerate the batch. |
| Splunk license state or competing volume is uncertain | Do not activate or expand ingestion. |
| Clock moves backward or forward | Continue from durable UTC bounds; never derive the lower bound from wall-clock polling time. |
| Ledger missing or corrupt | Stop. Reconcile from manifests and Splunk searches under a separately approved recovery plan. |

No failure path automatically deletes indexed events, clears Splunk checkpoints, resets the
ledger, rewinds the LimaCharlie checkpoint, or republishes archived batches.

## Governance and approval boundaries

Implementation creates local planning and validation capabilities first. The following live
effects remain separate approval-gated actions:

1. Install the official LimaCharlie CLI.
2. Authenticate the CLI to the exact organization; Andrew performs credential entry.
3. Install or update the Splunk parsing configuration.
4. Install or update the Splunk monitored input.
5. Restart or reload Splunk configuration after verifying every listener remains loopback-only.
6. Install and load the macOS LaunchAgent.
7. Activate the seven-day historical import.
8. Activate continuing five-minute collection.

Before the Splunk monitor or historical import is approved, preflight must establish:

- no overlapping monitored input or prior bridge sourcetype/source coverage;
- expected detection count, normalized bytes, and seven-day time range;
- current license-day usage, pending reservations, competing monitored bytes, and remaining
  operational headroom;
- exact index, source, sourcetype, host transform, and timestamp behavior;
- complete negative and positive parsing tests;
- the ready directory is empty until approval; and
- Splunk Web, management, HEC, and all sidecars remain loopback-only.

A changed organization, stream, historical range, interval, index, sourcetype, parsing contract,
CLI version, or monitor configuration invalidates the relevant proposal.

## Privacy, secrets, and logging

- Credentials remain in the official authenticated client and never enter repository files,
  LaunchAgent configuration, command arguments, logs, fixtures, receipts, or test snapshots.
- Operational logs contain IDs, counts, hashes, timestamps, and bounded error classes—not full
  detection bodies.
- Complete detections remain only in the restricted ignored spool and Splunk.
- Test fixtures are synthetic and contain no copied production detection payloads.
- Error messages are passed through the repository's redaction boundary before persistence.

## Testing strategy

### Unit tests

- exact CLI command construction and executable/version enforcement
- UTC window slicing, overlap, safety lag, restart, and clock-shift behavior
- complete pagination, cursor expiry, bounded retry, and incomplete-page rejection
- native-ID and canonical-hash deduplication
- conflicting content for one native ID
- duplicate-key, malformed, oversized, wrong-organization, missing-host, and invalid-time records
- deterministic envelopes, batch IDs, manifests, and canonical hashes
- atomic staging-to-ready publication and interrupted-write recovery
- SQLite transaction, checkpoint, and corruption behavior
- spool ceilings and singleton locking
- secret redaction and prompt-injection strings remaining inert data

### Contract tests

- official CLI version and structured-output fixture contract
- synthetic LimaCharlie detection schema variations
- Splunk NDJSON line breaking, timestamp extraction, per-record host mapping, source, index, and
  sourcetype
- zero truncation and exactly one parsed event per line
- exact batch-ID and detection-ID verification searches

### Integration tests

- fake paginated CLI output through the complete staging, ledger, and ready flow
- repeated overlapping windows produce no duplicate ready records
- restart after each publication boundary converges to one batch and one ledger identity
- Splunk-down accumulation stops at the spool ceiling and resumes without widening scope
- a seven-day synthetic backfill divided into bounded windows completes without gaps

### Narrow live validation

After separate approval, run one bounded detection-only query without publishing a batch. Record
count, time range, pagination completeness, schema coverage, and normalized byte estimate. Then
create a separate proposal for a minimal live batch, verify its exact Splunk count and metadata,
and only afterward propose the remaining seven-day import and recurring schedule.

## Acceptance criteria

The bridge is ready for recurring activation only when:

1. The official client is authenticated outside the repository and read-only detection queries
   succeed for the exact organization.
2. Seven-day preflight reports complete pagination, exact counts, normalized bytes, schema
   exceptions, and Splunk budget headroom without publishing data.
3. Every accepted record has a deterministic unique identity, source host, and event time.
4. Repeated and overlapping query windows produce no duplicate published identities.
5. Interrupted runs recover without gaps, widened scope, or automatic destructive cleanup.
6. Splunk parses one event per line with the approved index, host, source, sourcetype, and time.
7. A minimal approved live batch produces an exact verified count and immutable receipt.
8. All observed Splunk listeners remain loopback-only after configuration reload or restart.
9. The LaunchAgent runs only while the user is logged in and contains no secret material.
10. Focused tests, the repository test suite, lint, and type checking pass.

## References

- [LimaCharlie query limits and pagination](https://docs.limacharlie.io/4-data-queries/query-limits-and-performance/)
- [LimaCharlie query CLI](https://docs.limacharlie.io/4-data-queries/query-cli/)
- [LimaCharlie event schemas](https://docs.limacharlie.io/8-reference/event-schemas/)
- [Splunk monitored file inputs](https://help.splunk.com/en/splunk-enterprise/get-data-in/get-started-with-getting-data-in/9.4/get-other-kinds-of-data-in/monitor-files-and-directories-with-splunk-enterprise)
- [Splunk `props.conf` reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.0-configuration-file-reference/props.conf)
- [Splunk `transforms.conf` reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.0-configuration-file-reference/transforms.conf)
- [`policies/splunk-ingest.yaml`](../../../policies/splunk-ingest.yaml)
