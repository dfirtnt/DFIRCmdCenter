# Implementation Plan: LimaCharlie-to-Splunk Detection Bridge

Date: 2026-09-24
Status: Planning only; no CLI installation, authentication, Splunk change, scheduler installation,
live query, or ingestion is authorized
Source design:
[LimaCharlie-to-Splunk Detection Bridge Design](../specs/2026-09-24-limacharlie-splunk-detection-bridge-design.md)

## Delivery boundary

Build and test the bridge with synthetic data first. The background job may eventually retrieve
and prepare detection batches every five minutes, but v1 must not publish a batch into Splunk's
monitored directory without an exact, unconsumed approval for that batch.

This plan therefore uses two independent checkpoints:

- **Collection checkpoint:** the highest complete LimaCharlie query bound whose results are
  durably prepared in the unmonitored spool.
- **Publication checkpoint:** the set of exact prepared batch IDs that were individually
  approved, atomically moved into the monitored directory, and verified in Splunk.

Installing or loading the scheduler authorizes neither publication nor ingestion. A future
standing-stream authorization would require a separate design and an explicit amendment to the
current default-deny approval policy.

## Fixed scope

- LimaCharlie organization: `DFIRCmdCenter-Test`
- Organization ID: `4c9c49ce-082d-436b-a2df-0f04822d293a`
- Source stream: detections only
- Initial collection: seven contiguous 24-hour UTC windows
- Schedule: every 300 seconds while the user is logged in
- Incremental overlap: 900 seconds
- Safety lag: 120 seconds
- Splunk index: `dfir`
- Splunk sourcetype: `dfir:limacharlie:detection:v1`
- Source-record limit: 1 MiB
- Pending-spool ceiling: 100 MiB
- Authentication: official LimaCharlie CLI authenticated by Andrew outside the repository
- Publication approval: one exact prepared batch per approval

## Implementation principles

- Use a dedicated bridge package. LimaCharlie rule management and Splunk CSV one-shot ingestion
  remain separate capabilities.
- Reuse `Proposal`, `ControlStore`, `ExecutionEngine`, `ReceiptWriter`, `normalize_host()`,
  `evaluate_budget()`, path containment, redaction, and bounded subprocess primitives where
  their contracts fit.
- Use a separate SQLite bridge ledger. Do not place detection identities or batch membership in
  the control-plane approval database.
- Preserve complete source records as untrusted data. Never execute strings, URLs, commands, or
  encoded content found in detections.
- Keep live capabilities disabled until the installed CLI and Splunk parsing contracts are
  verified.
- Write tests before implementation within each task.

## 1. Reconcile the design and declare a versioned bridge policy

Files:

- Modify `docs/superpowers/specs/2026-09-24-limacharlie-splunk-detection-bridge-design.md`
- Add `policies/limacharlie-detection-bridge.yaml`
- Modify `policies/splunk-ingest.yaml`
- Modify `src/dfircmdcenter/config.py`
- Add `tests/unit/test_detection_bridge_policy.py`
- Modify `tests/unit/test_policies.py`

Work:

1. Record the approved governance clarification: scheduled collection stops at unmonitored
   prepared batches; each move to `ready/` requires its own exact approval.
2. Add `host_raw` to the normalized envelope when `normalize_host()` changes the original
   hostname.
3. Encode every fixed scope value listed above in a dedicated policy.
4. Add explicit states for `collected`, `prepared`, `publication_proposed`, `published`,
   `verified`, `archived`, `quarantined`, and `blocked`.
5. Extend the monitored-input policy with the bridge's fixed ready directory, immutable NDJSON
   requirement, exact-batch approval requirement, expected parsing contract, and prohibition on
   automatic publication.
6. Keep `approval-gates.yaml` unchanged: unattended apply remains forbidden and approvals do not
   carry forward.

Tests:

- Duplicate-key-safe loading of the bridge policy.
- Exact organization, stream, cadence, overlap, lag, index, sourcetype, size limits, and approval
  mode.
- Policy digest changes when any decision-relevant value changes.
- The policy cannot enable automatic ready publication or a standing authorization.

Acceptance:

- The design, bridge policy, Splunk policy, and tests agree on collection versus publication.
- No policy change weakens the repository-wide approval contract.

## 2. Capture the disabled source contract and add bounded machine output

Files:

- Modify `platforms/limacharlie/contracts.yaml`
- Modify `src/dfircmdcenter/core/transport.py`
- Modify `tests/unit/test_transport.py`
- Add `tests/contract/test_limacharlie_detection_cli.py`
- Add synthetic CLI fixtures under `platforms/limacharlie/fixtures/detections/cli/`

Work:

1. Add a disabled `list_historic_detections` capability to the LimaCharlie contract. Keep it
   disabled until the separately installed official CLI supplies a verified executable path,
   version, argument shape, authentication-context behavior, JSON framing, query time axis,
   boundary inclusivity, pagination termination, cursor expiry, and retry classifications.
2. Extend `SubprocessTransport` with a separate machine-output method/result that returns bounded
   raw stdout bytes to the requesting adapter without changing the current human-visible
   `run()` behavior.
3. Preserve strict executable and argument allowlists, clean environment, no shell, process-group
   termination, byte/line/runtime bounds, and safe diagnostics.
4. Reject invalid UTF-8 at the detection parser boundary. Do not replacement-decode evidence
   bytes.
5. Never include machine output, stderr bodies, environment values, or credentials in
   diagnostics, exceptions, representations, or persistent logs.
6. Pass only verified non-secret environment needed for the official client to locate its
   externally authenticated profile. Do not inspect or copy credential files.

Tests:

- Existing `run()` filtering remains unchanged.
- Machine output returns exact bounded bytes.
- Exact executable/argument enforcement, no shell, clean environment, timeout cleanup, line and
  byte caps, invalid output, and non-zero exit handling.
- Authentication-error stderr is classified without exposing its body.
- No raw output appears in diagnostics or exception text.

Acceptance:

- Synthetic contract tests pass while the live capability remains disabled.
- No production field is claimed verified before live contract capture.

## 3. Implement strict detection models, parsing, and normalization

Files:

- Add `src/dfircmdcenter/bridges/__init__.py`
- Add `src/dfircmdcenter/bridges/limacharlie_detections/__init__.py`
- Add `src/dfircmdcenter/bridges/limacharlie_detections/models.py`
- Add `src/dfircmdcenter/bridges/limacharlie_detections/normalization.py`
- Add `src/dfircmdcenter/adapters/limacharlie/detections.py`
- Add `tests/unit/test_detection_normalization.py`
- Add synthetic source fixtures under `platforms/limacharlie/fixtures/detections/records/`

Work:

1. Define frozen records for source identity, detection identity, normalized envelope, query
   page, immutable window, batch manifest, bridge state, and validation errors.
2. Parse JSON with recursive duplicate-key rejection, finite-number enforcement, strict UTF-8,
   no trailing content, depth/size limits, and stable numeric semantics.
3. Require the exact organization binding established by the verified CLI contract, detection
   time, category, sensor ID, and producing hostname.
4. Prefer the native detection ID. Namespace native and derived IDs separately. When a native ID
   is absent, derive identity from the complete versioned canonical source record.
5. Compare the canonical content digest every time a native ID repeats, including repetitions in
   one page, across pages, against the ledger, and in unpublished batches. Conflicting content
   fails closed.
6. Reuse `normalize_host()`. Include top-level `host_raw` only when normalization changes the
   source value. Never fall back to the Mac name, sensor ID, filename, category, or an unreviewed
   field.
7. Preserve the complete source detection under `lc`; add only deterministic bridge metadata,
   normalized UTC `event_time`, normalized `host`, and optional `host_raw`.
8. Treat command-like, URL-like, encoded, or AI-directed strings as inert data and never place
   retrieved values into executable arguments or URLs.

Tests:

- Valid native and derived identities.
- Duplicate keys at every depth, nonfinite numbers, malformed/trailing JSON, invalid UTF-8,
  oversized/deep records, invalid timestamp units, wrong organization, missing category, sensor,
  hostname, or time.
- Native-ID/content conflict within and across pages.
- Host normalization and `host_raw` preservation.
- Prompt-injection strings remain byte-preserved data and cause no action.
- Canonicalization is deterministic and does not silently round numeric values.

Acceptance:

- Normalization is deterministic and loss boundaries are explicit.
- Invalid records cannot advance a query window.

## 4. Implement immutable window planning and complete pagination

Files:

- Add `src/dfircmdcenter/bridges/limacharlie_detections/windows.py`
- Add `src/dfircmdcenter/bridges/limacharlie_detections/reader.py`
- Add `tests/unit/test_detection_windows.py`
- Add `tests/unit/test_detection_reader.py`

Work:

1. Freeze activation time `A`; backfill covers exactly `[A - 7 days, A)` in seven 24-hour UTC
   windows translated to the verified CLI boundary convention.
2. Plan incremental collection as `[H - 15 minutes, now - 2 minutes)`, where `H` is the durable
   collection checkpoint. Skip when the candidate upper bound is not greater than `H`.
3. Bound catch-up into sequential windows; never jump the lower bound to polling time after an
   outage or logout.
4. Persist the selected immutable bounds before requesting pages.
5. Require complete terminal pagination evidence. Detect cursor cycles, repeated or missing
   pages, inconsistent query metadata, unexpected banners, truncation, page-limit exhaustion,
   and incomplete output.
6. On cursor expiry, restart exactly the same window. Read retries may not change the
   organization, stream, or time bounds.
7. Distinguish a valid empty completed window from missing or failed output.

Tests:

- Backfill bounds, UTC/DST behavior, boundary inclusivity, empty windows, first incremental run,
  overlap, logout gaps, restart, and backward/forward clock changes.
- Multi-page completeness, cursor cycles, expiry restart, page duplication, truncation,
  unexpected output, and bounded retry.
- No source window advances on partial results.

Acceptance:

- Every collected window has immutable source bounds and complete pagination evidence.

## 5. Build the independent ledger and crash-safe prepared spool

Files:

- Add `src/dfircmdcenter/bridges/limacharlie_detections/ledger.py`
- Add `src/dfircmdcenter/bridges/limacharlie_detections/spool.py`
- Add `src/dfircmdcenter/bridges/limacharlie_detections/recovery.py`
- Add `tests/unit/test_detection_ledger.py`
- Add `tests/unit/test_detection_spool.py`
- Add `tests/integration/test_detection_bridge_recovery.py`

Work:

1. Create a dedicated SQLite ledger under
   `var/splunk/limacharlie-detections/state/`. Track schema version, activation identity, source
   windows, identities/content hashes, prepared batches, membership, publication proposals,
   publication state, Splunk verification, and archive state.
2. Treat a missing ledger for an existing activation/spool as corruption. Never silently create
   a fresh deduplication state over existing files.
3. Create restricted `staging/`, `prepared/`, `ready/`, `archive/`, `quarantine/`, `state/`,
   `receipts/`, and `logs/` directories with `0700` modes and `0600` files. Only `ready/` may
   later be monitored.
4. Derive batch IDs from policy identity, immutable window identity, and ordered detection
   identities/content hashes. Exclude the batch ID from its own hash material.
5. Freeze `collected_at`, membership, bytes, record count, and manifest once prepared.
6. Prepare a window by writing and syncing NDJSON and manifest files in staging, validating
   counts/hashes/modes/capacity, recording all identities and membership transactionally, then
   atomically moving the complete pair into unmonitored `prepared/`.
7. Advance only the collection checkpoint after every prepared artifact matches the ledger.
   Publication state remains untouched.
8. Reconcile ledger, staging, prepared, ready, archive, and quarantine before every new source
   query. Adopt a matching completed rename after a crash; never rebuild different bytes.
9. Count staged, prepared, and unverified-ready reservation bytes against the 100 MiB ceiling,
   including temporary duplication. Stop before growth when capacity is insufficient.
10. Never delete automatically. Archive only after exact Splunk verification and a separately
    authorized archive transition.

Tests:

- Permissions, symlink/path escape, initialization identity, schema migration refusal, SQLite
  corruption, deduplication, conflicting identities, deterministic batch IDs, multi-batch and
  zero-new-record windows, and spool capacity.
- Fault injection after each file write, fsync, directory sync, transaction, rename, and
  checkpoint boundary.
- Disk-full and target-collision behavior.
- Repeated recovery converges without republishing or changing bytes.

Acceptance:

- Automatic collection can safely stop at `prepared/` without exposing any file to Splunk.
- Collection and publication checkpoints cannot be confused or advanced together.

## 6. Implement exact batch proposals and approval-gated publication

Files:

- Add `src/dfircmdcenter/bridges/limacharlie_detections/proposals.py`
- Add `src/dfircmdcenter/bridges/limacharlie_detections/publication.py`
- Modify `policies/approval-gates.yaml` only to name the scoped new operations without weakening
  existing controls
- Add `tests/unit/test_detection_bridge_governance.py`
- Modify `tests/unit/test_splunk_governance.py`

Work:

1. Build one `Proposal` for one exact prepared batch. Bind organization, window, batch ID, file
   and manifest paths, hashes, byte count, record count, complete detection-identity digest,
   event-time range, host set, index, source, sourcetype, policies, platform contracts, parsing
   configuration, active monitor inventory, indexed coverage, current license day, measured
   usage, pending reservations, competing bytes, and expiry.
2. Reuse `evaluate_budget()` and reserve the exact proposed bytes transactionally. A 100 MiB
   spool ceiling is not license authorization.
3. Unknown coverage, partial prior external coverage, monitor overlap, budget uncertainty,
   reset-boundary uncertainty, parsing uncertainty, or changed preconditions blocks proposal or
   apply.
4. Use `ExecutionEngine` to consume the exact approval, revalidate immediately before the
   publish effect, and atomically rename only that batch from `prepared/` to `ready/` without
   overwrite.
5. An ambiguous publication outcome enters unknown state and is reconciled by ledger/filesystem
   reads. Never automatically rename or republish again.
6. The scheduler and collection runner may create proposals but may never approve or publish
   them.
7. Do not enable a generic global `apply` surface. Add a narrow batch-publication handler whose
   target key includes the exact batch ID.

Tests:

- Proposal digest changes for any batch, scope, policy, contract, parsing, monitor, coverage,
  budget, or path change.
- Approval cannot be reused for a sibling batch, retried publish, changed source, or later
  version.
- Scheduler code cannot invoke publication.
- Stale and ambiguous outcomes fail closed and reconcile read-only.
- Reservations prevent two approvals from oversubscribing the Splunk operational ceiling.

Acceptance:

- No path from recurring collection to `ready/` exists without a consumed exact batch approval.

## 7. Implement the Splunk NDJSON contract and verification

Files:

- Add `platforms/splunk/sourcetypes/limacharlie-detection-v1/inputs.conf.example`
- Add `platforms/splunk/sourcetypes/limacharlie-detection-v1/props.conf`
- Add `platforms/splunk/sourcetypes/limacharlie-detection-v1/transforms.conf`
- Modify `platforms/splunk/contracts.yaml`
- Add `src/dfircmdcenter/adapters/splunk/detection_monitor.py`
- Add `src/dfircmdcenter/adapters/splunk/detection_verification.py`
- Add `tests/contract/test_splunk_detection_parsing.py`
- Add `tests/unit/test_splunk_detection_verification.py`

Work:

1. Restrict the monitor to the exact `ready/` directory and batch filename pattern; manifests and
   every other spool directory remain excluded.
2. Fix index, source, and sourcetype; parse one NDJSON line as one event; set `_time` from the
   normalized UTC `event_time`; derive Splunk `host` from the reviewed top-level normalized host;
   and extract JSON once.
3. Define a separate maximum serialized envelope size and prove Splunk does not truncate it.
4. Test nested source content containing misleading `host`, `event_time`, newlines, braces, and
   escaped strings so it cannot override top-level metadata.
5. Review small-file CRC/fingerprinting, rename, restart, and archived-file behavior. Do not add
   `crcSalt` without evidence that it cannot cause reindexing.
6. Keep `change_index_or_input_config` disabled until an approved synthetic Splunk 10.4.3 parsing
   validation proves the exact configuration digest.
7. Verify published batches with fixed search templates and validated IDs. Require completed,
   paginated search results and compare exact identity sets and multiplicities, count, batch ID,
   host, time, source, index, and sourcetype.
8. Missing, partial, timed-out, or failed searches remain unknown; they never mean zero indexed
   events.
9. Write an immutable receipt only after exact verification. Leave unverified files in `ready/`.

Tests:

- Static configuration shape and one-event-per-line parsing fixtures.
- UTC `_time`, per-record host and `host_raw`, fixed metadata, no duplicate extraction, and no
  truncation.
- Exact verification identities and multiplicities, pagination completeness, timeout/failure,
  and mismatched metadata.
- Rename/restart/fingerprint behavior in the approved synthetic live validation stage.

Acceptance:

- Static tests pass without claiming that Splunk 10.4.3 has been live-validated.

## 8. Add the collection runner and inert login scheduler artifact

Files:

- Add `src/dfircmdcenter/bridges/limacharlie_detections/runner.py`
- Add `src/dfircmdcenter/bridges/limacharlie_detections/scheduler.py`
- Add
  `platforms/limacharlie/launchagents/com.dfircmdcenter.limacharlie-detections.plist.example`
- Add `tests/unit/test_detection_runner.py`
- Add `tests/unit/test_detection_scheduler.py`

Work:

1. Implement preview, approved one-time backfill collection, and recurring collection modes.
   Preview reports metadata only and changes no bridge checkpoint.
2. Run recovery before querying and acquire a non-blocking singleton lock. A concurrent
   invocation records only bounded `already_running` metadata and exits safely.
3. Validate directory ownership/modes, fixed policy digest, source contract, organization, CLI
   identity/version, and capacity before each run.
4. Render an inert per-user LaunchAgent using absolute paths, `RunAtLoad`, and a 300-second
   interval. Include no secrets, mutable shell command, shell expansion, or inherited credential
   value.
5. The scheduled command may collect and prepare only. It cannot publish, approve, change Splunk,
   start Splunk, archive, delete, or reset state.
6. Keep LaunchAgent installation/loading outside the repository and separately approval-gated.

Tests:

- Locking, safe concurrency, recovery ordering, auth/version/config drift, capacity exhaustion,
  logout catch-up, and staging-only behavior.
- Deterministic plist rendering and validation; no secret-shaped fields or publication command.
- Import-level test proving scheduler modules do not depend on publication execution handlers.

Acceptance:

- Loading the eventual scheduler cannot cause Splunk ingestion by itself.

## 9. Expose narrow commands and document operations

Files:

- Add `src/dfircmdcenter/bridge_commands.py`
- Modify `src/dfircmdcenter/cli.py`
- Add `tests/integration/test_detection_bridge_cli.py`
- Add `docs/runbooks/limacharlie-splunk-detection-bridge.md`
- Modify `platforms/limacharlie/README.md`
- Modify `platforms/splunk/README.md`
- Modify `README.md`

Commands:

```text
dfirctl limacharlie detections status
dfirctl limacharlie detections preflight
dfirctl limacharlie detections preview
dfirctl limacharlie detections collect-once
dfirctl limacharlie detections plan-publish BATCH_ID
dfirctl limacharlie detections publish PROPOSAL_ID
dfirctl limacharlie detections verify BATCH_ID
dfirctl limacharlie detections reconcile BATCH_ID
```

Work:

1. Keep status, preflight, and preview metadata-only. Never print complete detection bodies.
2. Require a separately enabled live source contract for collection commands.
3. Make fixture mode incapable of installing, authenticating, publishing, verifying live
   Splunk, or loading a scheduler.
4. Require the narrow publication command to resolve one exact approved proposal and batch.
5. Document the difference between collection, preparation, publication, Splunk indexing,
   verification, and archiving.
6. Document recovery rules, pending-spool ceiling, fixed late-arrival guarantee, operator
   responsibilities, and every separate live approval boundary.

Tests:

- Help works without platform access.
- Fixture commands make no network calls and cannot publish.
- Output is stable, redacted metadata.
- Missing, stale, mismatched, or consumed approval prevents publication.
- CLI command separation mirrors the two checkpoints.

Acceptance:

- The command surface does not imply that preparation equals ingestion or verification.

## 10. Local verification and separately approved rollout

Run focused checks after each task, then the full local suite:

```bash
uv run pytest tests/unit/test_transport.py
uv run pytest tests/unit/test_detection_bridge_policy.py tests/unit/test_detection_normalization.py
uv run pytest tests/unit/test_detection_windows.py tests/unit/test_detection_reader.py
uv run pytest tests/unit/test_detection_ledger.py tests/unit/test_detection_spool.py
uv run pytest tests/integration/test_detection_bridge_recovery.py
uv run pytest tests/unit/test_detection_bridge_governance.py
uv run pytest tests/contract/test_splunk_detection_parsing.py
uv run pytest tests/unit/test_splunk_detection_verification.py
uv run pytest tests/unit/test_detection_runner.py tests/unit/test_detection_scheduler.py
uv run pytest tests/integration/test_detection_bridge_cli.py
uv run pytest
uv run ruff check .
uv run mypy src
```

Do not install dependencies implicitly. Use the existing environment.

Live rollout remains outside implementation authorization and occurs only through separate exact
proposals in this order:

1. Install the official LimaCharlie CLI, if still absent.
2. Andrew authenticates the CLI externally to the exact organization.
3. Capture the CLI version and exact read-only detection-query contract.
4. Approve one bounded metadata-only schema query.
5. Approve synthetic Splunk parsing validation against the exact configuration digest.
6. Collect the seven-day candidate into unmonitored restricted `prepared/` storage and report
   complete pagination, count, time range, normalized bytes, and exceptions.
7. Approve parsing configuration installation.
8. Approve monitor installation while `ready/` is empty.
9. Approve any required Splunk reload or restart; verify every listener remains loopback-only.
10. Propose one minimal prepared batch with current coverage and license state.
11. Approve and publish that exact batch; verify identities, count, metadata, license usage, and
    receipt.
12. Recompute coverage and budget, then propose each remaining historical batch individually.
13. Complete and verify historical publication before installing the scheduler.
14. Approve installation/loading of the staging-only LaunchAgent.
15. Verify one scheduled collection cycle and logout/login recovery; prepared batches remain
    unindexed until individually approved.

Stop on any changed prerequisite, listener exposure, incomplete query, parsing mismatch,
identity conflict, overlap uncertainty, budget uncertainty, unverified batch, or ambiguous write.

## Definition of done

Implementation is complete when:

1. All offline and synthetic tests pass, including crash-boundary and authorization tests.
2. The live detection capability remains disabled until its installed CLI contract is verified.
3. Scheduled collection cannot reach the monitored directory.
4. Every prepared batch has deterministic identity, immutable bytes, complete pagination, and a
   separate collection checkpoint.
5. Every published batch consumes one exact approval and verifies exact identities and metadata
   in Splunk.
6. Credentials never enter repository files, arguments, logs, fixtures, manifests, receipts, or
   scheduler configuration.
7. No live configuration or ingestion is represented as complete without its separate approved
   execution and verification evidence.
