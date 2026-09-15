# DFIR Command Center Implementation Plan

Date: 2026-09-14

Source specification: `docs/superpowers/specs/2026-09-14-dfircmdcenter-design.md`

## Outcome

Build an attended, approval-gated Python CLI named `dfirctl` that can safely read, plan, apply, and verify supported operations for Action1, LimaCharlie, the local Velociraptor server, and the local Splunk Free server.

Implementation is complete only after the fixture and contract suites pass and read-only status works for all four adapters. Live mutations remain separate, exact, user-approved operations; completing the code does not authorize them.

## Technical baseline

- Python package under `src/dfircmdcenter/`
- Python `>=3.12`
- `uv` for environment and lockfile management
- `httpx` for bounded HTTP clients
- `PyYAML` with a duplicate-key-rejecting safe loader
- `pytest`, `pytest-cov`, `ruff`, and `mypy` for validation
- Standard-library `sqlite3`, `csv`, `zoneinfo`, `hashlib`, `subprocess`, and `pathlib`
- No shell interpolation, dynamic `eval`, arbitrary REST, arbitrary VQL, or arbitrary SPL surfaces

The initial CLI is synchronous. These operations are administrative and bounded; async infrastructure would add complexity without improving the first release.

## Safety decisions resolved for implementation

### Approval model

Chat approval is the authority boundary. The local approval record is an attended safety interlock and audit aid, not cryptographic proof of human identity.

`dfirctl proposal approve` may be invoked only after Andrew approves the exact proposal in this chat. It records the proposal digest and a non-secret chat reference. `dfirctl apply` consumes that record once. Retrieved platform content can never create or satisfy an approval.

There is no unattended apply mode in the first release.

### Private and version-controlled state

Full snapshots, target mappings, evidence paths, working files, approvals, locks, and receipts live under ignored `var/` with restricted permissions. Only allowlisted public projections, policies, fixture data, schemas, and rule definitions may be version controlled.

### Velociraptor datastore extraction

The normal path is a supported Velociraptor flow or hunt export. Direct datastore-derived extraction is allowed only for an exact finished flow and only through the pinned DFIRMedic helper after containment preflight and post-extraction validation.

If decoded paths escape the fresh output directory, collide, involve symlinks, exceed limits, or cannot be mapped deterministically, extraction stops and the supported export path is used. Helper exit zero alone never proves completeness.

### Splunk budget

The 400 MB operational ceiling is exactly `400_000_000` source bytes per Splunk license day. The calculation also reserves pending ingestion attempts and accounts conservatively for measurement lag and competing monitored inputs. Unknown usage or reset-boundary semantics blocks ingestion.

## Target structure

```text
DFIRcmdCenter/
  AGENTS.md
  README.md
  pyproject.toml
  uv.lock
  .gitignore
  policies/
    approval-gates.yaml
    splunk-ingest.yaml
  platforms/
    action1/
      README.md
      contracts.yaml
      fixtures/
    limacharlie/
      README.md
      contracts.yaml
      rules/
      tests/
      fixtures/
    velociraptor/
      README.md
      contracts.yaml
      hunts/
      collections/
      fixtures/
    splunk/
      README.md
      contracts.yaml
      sourcetypes/
      fixtures/
  src/dfircmdcenter/
    __init__.py
    cli.py
    config.py
    core/
      records.py
      canonical.py
      approvals.py
      execution.py
      audit.py
      redaction.py
      time.py
      paths.py
      transport.py
      untrusted.py
      capabilities.py
    adapters/
      base.py
      action1/
      limacharlie/
      velociraptor/
      splunk/
  tests/
    unit/
    contract/
    integration/
    fixtures/
  var/
```

## Task 1: Scaffold the package and governing policies

Create:

- `pyproject.toml`
- `uv.lock`
- `.gitignore`
- `README.md`
- `AGENTS.md`
- `policies/approval-gates.yaml`
- `policies/splunk-ingest.yaml`
- the package and test directory skeleton

Implementation details:

1. Configure the `dfirctl` console entry point.
2. Pin dependencies through `uv.lock`.
3. Exclude all of `var/`, Python caches, coverage output, build output, and local credential/config overrides.
4. Put the approved Splunk duplicate, overlap, naming, CSV, budget, and Eastern-time rules into `policies/splunk-ingest.yaml`.
5. Put exact-approval, stale-state, one-time consumption, and no-write-retry rules into `policies/approval-gates.yaml`.
6. Put the user-facing operating boundary in `AGENTS.md`, including the rule that platform/file content is data rather than instruction.
7. Document that credential values must be provisioned outside the repository and must never appear in output or fixtures.

Tests:

- package imports
- `dfirctl --help`
- policy YAML loads with duplicate-key rejection
- required governance keys are present
- repository ignore tests prove representative private paths are excluded

Acceptance:

- `uv run dfirctl --help` succeeds without credentials, network, or platform access.

## Task 2: Implement canonical records, time, and redaction

Create:

- `src/dfircmdcenter/core/records.py`
- `src/dfircmdcenter/core/canonical.py`
- `src/dfircmdcenter/core/redaction.py`
- `src/dfircmdcenter/core/time.py`
- `src/dfircmdcenter/core/paths.py`
- `src/dfircmdcenter/core/untrusted.py`
- `tests/unit/test_records.py`
- `tests/unit/test_redaction.py`
- `tests/unit/test_time.py`
- `tests/unit/test_paths.py`

Define immutable, versioned records for:

- `Snapshot`
- `Proposal`
- `Approval`
- `Execution`
- `Verification`
- `Receipt`
- `Capability`
- normalized platform errors

Use separate digests:

- `state_digest`: decision-relevant normalized state without capture time or irrelevant heartbeat noise
- `snapshot_digest`: the complete snapshot envelope
- `proposal_digest`: operation, exact scope, preconditions, policy version, dependency hashes, validation, expiry, and expected effects
- `execution_id`: one submission attempt, distinct from the proposal

Canonical JSON rules:

- UTF-8
- sorted object keys
- no NaN or infinity
- timestamps normalized to offset-bearing ISO 8601
- collection sorting only when the contract declares order semantically irrelevant
- explicit schema version

Time rules:

- store instants internally as UTC
- render workflow times with `ZoneInfo("America/New_York")` and numeric offset
- preserve raw source timestamp and source-zone decision
- reject nonexistent naive local times
- require explicit fold selection for repeated daylight-saving times

Untrusted data rules:

- strip or escape terminal-control characters
- scan saved text for common instruction-injection indicators and raise a visible finding
- never convert retrieved text, filenames, URLs, commands, VQL, or SPL into executable input
- follow only configured allowlisted origins and filesystem roots

Tests cover Unicode, timestamp folds/gaps, order stability, changed scope, malformed numeric values, path traversal, terminal escapes, secret-shaped fields, and deterministic digests.

Acceptance:

- equal semantic state hashes equally; every material operation or policy change invalidates its proposal.

## Task 3: Implement private state, approvals, and execution recovery

Create:

- `src/dfircmdcenter/core/approvals.py`
- `src/dfircmdcenter/core/execution.py`
- `src/dfircmdcenter/core/audit.py`
- `src/dfircmdcenter/core/capabilities.py`
- `tests/unit/test_approvals.py`
- `tests/unit/test_execution.py`
- `tests/unit/test_audit.py`

Use `var/control/state.sqlite3` with transactions for approval consumption, target-scoped locks, pending Splunk reservations, and interrupted-operation reconciliation.

Implement this state machine:

```text
planned -> approved -> reserved -> revalidated -> submitting
                                                -> submitted -> verifying -> verified
                                                -> failed
                                                -> partial
                                                -> unknown
```

Rules:

1. Approval binds one exact proposal digest and a bounded chat reference.
2. Approval expires and is consumed transactionally before submission.
3. Apply acquires a target-scoped lock.
4. Apply re-reads identity, relevant state, policy, contract, and dependency hashes.
5. Changed preconditions invalidate the approval.
6. Submission intent is persisted before the mutation begins.
7. Ambiguous write outcomes enter `unknown`; they are reconciled with reads and are never automatically retried.
8. Subsequent mutations require a new proposal and approval.
9. Final receipts use exclusive creation and atomic publication.

Treat the audit as consistency evidence, not tamper-proof independent authorization.

Tests cover missing, expired, mismatched, reused, and fabricated approvals; two-process consumption races; target drift; crashes at each submission boundary; ambiguous server acceptance; atomic receipt writes; and recovery by read-only reconciliation.

Acceptance:

- no adapter mutation can bypass the common execution engine.

## Task 4: Add safe transport and adapter contracts

Create:

- `src/dfircmdcenter/core/transport.py`
- `src/dfircmdcenter/adapters/base.py`
- `tests/unit/test_transport.py`
- `tests/contract/test_adapter_contract.py`
- `platforms/*/contracts.yaml`

Define a common adapter protocol for:

- capabilities
- identity
- status snapshot
- proposal construction
- revalidation
- submit
- verify or reconcile

HTTP transport:

- fixed configured vendor origins
- bounded connect/read/overall timeouts
- bounded response size
- authorization headers and token responses never logged
- read-only retry policy with jitter and `Retry-After`
- no generic retry middleware on writes
- ambiguous errors distinguish pre-transmission failure from unknown post-transmission outcome when possible

Subprocess transport:

- argument arrays with `shell=False`
- fixed executable allowlist
- clean bounded environment
- output byte and line limits
- platform-specific stdout/stderr allowlists and redaction
- no broad process or configuration dumps

Contract files record verified platform version/API surface, required permissions, pagination, rate limits, conditional-update support, idempotency support, and enabled operations. Unknown or incompatible contracts disable the affected write capability.

Acceptance:

- fixture adapters run without credentials or live services; unsafe command, URL, query, or output paths are rejected.

## Task 5: Deliver read-only status across all platforms

Create the initial modules under all four `src/dfircmdcenter/adapters/<platform>/` packages and fixture datasets under `platforms/<platform>/fixtures/`.

Add:

```text
dfirctl status
dfirctl status action1
dfirctl status limacharlie
dfirctl status velociraptor
dfirctl status splunk
```

Status scope:

- Action1: API identity, organizations, relevant endpoints, packages, automations, and deployment status
- LimaCharlie: organization identity, D&R inventory, enabled state, version data, and complete metadata needed for later safe changes
- Velociraptor: binary/API identity, clients, hunts, flows, selected artifact definitions, and pinned DFIRMedic helper hashes
- Splunk: version, safe local binding summary, `dfir` index state, effective monitor input summary, license type, current-day usage, and reset boundary

Requirements:

- detect incomplete pagination
- report denied permissions and unavailable fields explicitly
- never dump environment variables, unrestricted stderr, full config files, tokens, or credential-bearing process arguments
- return `unknown`, not a false healthy state, when live status is ambiguous

Tests use paginated, truncated, denied, malformed, rate-limited, and secret-bearing fixture responses.

Acceptance:

- all status commands work from fixtures; separately approved live read checks produce redacted bounded output without mutation.

## Task 6: Implement Splunk CSV governance and one-shot ingestion

Create:

- `src/dfircmdcenter/adapters/splunk/client.py`
- `src/dfircmdcenter/adapters/splunk/status.py`
- `src/dfircmdcenter/adapters/splunk/naming.py`
- `src/dfircmdcenter/adapters/splunk/timestamps.py`
- `src/dfircmdcenter/adapters/splunk/csv_normalization.py`
- `src/dfircmdcenter/adapters/splunk/coverage.py`
- `src/dfircmdcenter/adapters/splunk/budget.py`
- `src/dfircmdcenter/adapters/splunk/ingest.py`
- `src/dfircmdcenter/adapters/splunk/receipts.py`
- `platforms/splunk/sourcetypes/README.md`
- Splunk fixtures and focused tests

Implement the pipeline:

1. Validate the immutable source CSV and hash it.
2. Parse CSV strictly, including quotes and multiline fields.
3. Reject ambiguous encoding/delimiter, malformed rows, duplicate headers, and normalized-header collisions.
4. Produce a deterministic normalized CSV plus field map while preserving the original.
5. Require explicit timestamp interpretation and host mapping.
6. Validate index `dfir`, sourcetype version, and effective parsing contract.
7. Inventory effective monitors, indexed coverage, and prior receipts.
8. Classify `new`, `exact_duplicate`, `partial_overlap`, `alternate_representation`, or `unknown`.
9. Calculate license headroom and reserve projected bytes under the ingestion lock.
10. Produce an exact one-shot proposal.
11. Revalidate original/normalized hashes, config, coverage, and budget.
12. Submit exactly once, verify indexed metadata and event coverage, then finalize the receipt.

Naming enforcement:

- index: `dfir` unless a separately approved index exists
- host: lowercase FQDN/short name for the producing system, with changed raw value preserved as `host_raw`
- sourcetype: `dfir:<producer>:<schema>:v<integer>`
- never use the ingesting Mac, filename, date, case ID, or automatic guessing as host/sourcetype metadata

Single-host CSVs use an explicit constant host. Multi-host CSVs remain blocked until their reviewed sourcetype contract proves per-row `MetaData:Host` assignment; a CSV field named `host` is not accepted as proof by itself.

Coverage combines source and normalized hashes, lineage, case/client/hunt/flow/artifact identifiers, reliable event identifiers, canonical row fingerprints, and indexed aggregate checks. Time-range overlap is a warning signal, not proof of duplication or independence.

For Splunk configuration, store reviewed sourcetype definitions in the project and render proposed `props.conf`/`transforms.conf` changes into ignored working output. Copying them into `/Users/starlord/splunk/etc/apps/dfircmdcenter/` and restarting Splunk are separate external changes requiring exact approval.

Tests:

- renamed exact duplicate
- raw versus normalized alternate representation
- partial row overlap
- unknown pre-existing coverage
- monitor-stanza overlap
- 399/400/401 MB boundaries
- measurement lag and concurrent reservations
- license rollover
- malformed, multiline, BOM, and non-UTF-8 CSVs
- timestamp `Z`, explicit offset, naive Eastern, daylight-saving fold, and daylight-saving gap
- index/host/sourcetype rejection
- partial indexing, timeout, and blocked resubmission

Acceptance:

- every governance rejection occurs before submission; a fixture success produces a complete immutable receipt.

## Task 7: Implement LimaCharlie rule lifecycle

Create:

- `src/dfircmdcenter/adapters/limacharlie/client.py`
- `src/dfircmdcenter/adapters/limacharlie/rules.py`
- `src/dfircmdcenter/adapters/limacharlie/validation.py`
- `src/dfircmdcenter/adapters/limacharlie/replay.py`
- `platforms/limacharlie/rules/*.yaml`
- `platforms/limacharlie/tests/*`
- LimaCharlie fixtures and focused tests

Implement separate planned operations for create, update, enable, disable, delete, and metadata change.

Rules:

- export live rules before planning
- preserve the complete current `usr_mtd` object when changing metadata
- reject concurrent rule or metadata drift
- safely load YAML with duplicate-key rejection
- allow only report-only response structures in the initial release
- bind validator results and tests to the exact rule digest
- require meaningful expected-match and expected-non-match events with correct event types
- require Replay for stateful rules and retain exact sensor/time scope in the proposal
- treat Replay job creation as its own approved operation when it consumes or persists platform resources
- require a new approval to deploy a rule after validation/replay

Add the initial Windows categories one reviewed rule at a time: persistence, credential access, suspicious PowerShell/LOLBin activity, remote-access abuse, and defense evasion.

Tests cover full metadata preservation, unknown response actions, false non-match tests, wrong rule-version validation, stateful Replay ordering, partial API errors, and stale live-rule snapshots.

Acceptance:

- a complete fixture rule lifecycle passes; no endpoint response action is possible.

## Task 8: Implement Velociraptor hunts, collections, exports, and extraction

Create:

- `src/dfircmdcenter/adapters/velociraptor/client.py`
- `src/dfircmdcenter/adapters/velociraptor/scope.py`
- `src/dfircmdcenter/adapters/velociraptor/collections.py`
- `src/dfircmdcenter/adapters/velociraptor/hunts.py`
- `src/dfircmdcenter/adapters/velociraptor/integrity.py`
- `src/dfircmdcenter/adapters/velociraptor/exports.py`
- `src/dfircmdcenter/adapters/velociraptor/helpers.py`
- `src/dfircmdcenter/adapters/velociraptor/provenance.py`
- `platforms/velociraptor/hunts/*.yaml`
- `platforms/velociraptor/collections/*.yaml`
- Velociraptor fixtures and focused tests

Use the API config only through the official client boundary; do not read or persist its secret-bearing contents. Pin the local 0.77.2 contract and hash the selected DFIRMedic artifacts/helpers at planning and application.

Collection proposals contain:

- exact client IDs
- reviewed artifact definitions and hashes
- parameters, timeout, resource limits, and upload limits
- expected result and upload classes
- estimated data volume and risk

Immediate label operations resolve to an immutable reviewed client list and revalidate membership. Standing hunts explicitly disclose that qualifying future clients will also run. These are different operation types.

Integrity verification:

- invoke `check-collection-logs.py` with exact client, flow, and datastore path
- preserve exit `0`, `1`, and `2` meanings exactly
- independently verify flow state, expected tables, expected uploads, and upload ceilings
- never convert zero rows or `FINISHED` into completeness by itself

Export:

- use `create_flow_download()` or `create_hunt_download()` through supported interfaces
- treat export preparation as an approved server operation
- poll with bounded reads
- write only under `var/velociraptor/exports/`
- record client/hunt/flow/artifact/source identifiers, settings, hashes, sizes, and integrity result

Datastore-derived extraction:

- require exact finished client/flow
- require a stable source inventory and fresh exclusive output directory
- precompute decoded destinations using the pinned helper behavior
- reject path escape, absolute components, symlinks, collisions, unexpected file types, and resource-limit excess
- invoke the helper only after preflight
- re-inventory source and output afterward
- verify expected counts, hashes, decompression state, truncation flags, and containment
- fail closed or use the supported export path on any uncertainty

Tests cover wrong client/flow, label changes, future standing-hunt scope, unavailable tools, malformed/missing logs, zero rows, incomplete uploads, export timeout, path traversal, decoded collisions, symlinks, helper hash drift, multi-stream zlib, and truncated output.

Acceptance:

- the fixture collection/export/extraction chain produces complete provenance while the control plane performs no datastore write.

## Task 9: Implement Action1 deployment lifecycle

Create:

- `src/dfircmdcenter/adapters/action1/client.py`
- `src/dfircmdcenter/adapters/action1/inventory.py`
- `src/dfircmdcenter/adapters/action1/deployments.py`
- `src/dfircmdcenter/adapters/action1/verification.py`
- Action1 fixtures and focused tests

Implement OAuth through a credential mechanism outside the repository. Request the narrow role permissions needed for each enabled capability. Never log client IDs together with secret material, bearer tokens, token responses, or authorization headers.

Read operations use bounded exponential backoff with jitter and documented `Retry-After` behavior. Keep request volume below the current documented limit. Write operations do not retry automatically.

Deployment proposals pin:

- organization ID
- exact endpoint ID
- package ID and version
- upstream and repackaged installer SHA-256
- client label/configuration provenance
- exact deployment settings
- expected installed version
- reviewed endpoint-to-Velociraptor identity correlation
- expected check-in window

Do not treat the unsigned personal MSI warning as failure, suppress it, or claim it is trusted. Verify Action1 installation status and installed version separately, then require a fresh matching Velociraptor check-in. Hostname alone is insufficient identity correlation.

If Action1 times out after request transmission, record `unknown`, save any returned operation ID, and reconcile by read-only deployment/status queries. Do not resubmit automatically.

Tests cover pagination, OAuth sanitization, permission denial, rate limiting, endpoint ambiguity, warning versus failure, timeout after acceptance, installed-version mismatch, and successful install without matching Velociraptor check-in.

Acceptance:

- a fixture deployment reaches verified only when both Action1 and Velociraptor checks pass.

## Task 10: Complete CLI integration, documentation, and non-live QA

Wire these bounded commands:

```text
dfirctl status [platform]
dfirctl <platform> plan <supported-operation> ...
dfirctl proposal show <proposal-id>
dfirctl proposal approve <proposal-id> --approval-ref <reference>
dfirctl apply <proposal-id>
dfirctl verify <execution-id>
dfirctl reconcile <execution-id>
dfirctl audit show <execution-id>
```

Do not add generic `exec`, raw query, arbitrary URL, arbitrary file destination, or force/bypass commands.

Write platform runbooks for:

- required permissions and credential provisioning boundary
- status and proposal fields
- exact expected effects
- approval expiry and consumption
- verification and ambiguous-outcome reconciliation
- recovery actions and their separate approval requirements
- Splunk CSV preparation and receipt interpretation
- Velociraptor flow/hunt/export provenance

Run:

```text
uv lock --check
uv run ruff check .
uv run mypy src
uv run pytest
uv run pytest --cov=src/dfircmdcenter --cov-report=term-missing
git diff --check
```

Acceptance:

- the complete fixture/unit/contract suite passes
- ordinary test commands perform no network call or live mutation
- failure output contains no fixture secret values
- README provides a safe first-use path beginning with read-only status

## Task 11: Separately approve and execute live acceptance

Live acceptance is not part of ordinary automated tests.

Sequence:

1. Run separately approved read-only identity/status checks for all four adapters.
2. Review contract/version/permission gaps and disable unsupported capabilities.
3. Generate one exact low-impact proposal at a time.
4. Ask for approval for that exact proposal.
5. Apply once and verify before considering another platform operation.

An export, Replay, rule change, hunt action, collection, Splunk configuration change, Splunk restart, index creation, ingestion, and Action1 deployment are separate consequential actions. Approval for one does not authorize another.

Suggested live order:

1. Splunk read-only status and governance preflight against a non-sensitive fixture CSV
2. Velociraptor read-only inventory and a user-selected existing flow export
3. LimaCharlie read-only rule export and validator-only test
4. Action1 read-only deployment-status reconciliation
5. Exact live mutations only when individually requested and approved

Completion status remains explicit:

- `verified`: live postcondition proven
- `partial`: some expected effects proven and others not
- `unknown`: submission may have occurred but live state cannot yet resolve it
- `fixture-only`: implementation works in tests but has not been live-verified

## Milestones

- **M1 — Safe foundation:** Tasks 1-4 complete; deterministic approval engine and safe transports pass concurrency/failure tests.
- **M2 — Read-only command center:** Task 5 complete; all four status adapters work against fixtures and approved live reads.
- **M3 — Platform workflows:** Tasks 6-9 complete; each operation lifecycle passes fixture tests.
- **M4 — Integrated release:** Task 10 complete; all non-live QA passes and documentation is current.
- **M5 — Live verification:** Task 11 performed only through separate approvals; results are recorded honestly as verified, partial, unknown, or fixture-only.
