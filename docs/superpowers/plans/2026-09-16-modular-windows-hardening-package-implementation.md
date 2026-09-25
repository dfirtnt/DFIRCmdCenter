# Implementation Plan: Modular Windows Hardening Packages

Date: 2026-09-16
Status: Planning only; no endpoint or platform write is authorized
Source design: [Modular Windows Hardening Package Design](../specs/2026-09-16-modular-windows-hardening-package-design.md)

## Recommended delivery boundary

Build the offline catalog, Windows 11 preflight/evidence model, dependency resolver, proposal generator, verification evaluator, profiles, CLI planning commands, and fixture-based tests. Keep every Action1, LimaCharlie, and Velociraptor write capability disabled.

The first implementation must not create an Action1 automation, change LimaCharlie configuration, launch a Velociraptor flow, enable a LimaCharlie response, or apply a Windows policy. It will make those future operations expressible as exact, individually approval-gated proposals after their platform contracts and live state are separately verified.

## Design decisions carried into implementation

- Use the existing immutable Proposal, ControlStore, ExecutionEngine, approval policy, audit receipt, and default-deny capability systems. Do not introduce a second approval database or a hardening platform enum.
- Model each hardening change as an Action1 proposal with one target, module ID/version, mode, action, immutable inputs, explicit verification requirements, and rollback/recovery text.
- Treat Action1, LimaCharlie, and Velociraptor observations as evidence inputs. A fresh Velociraptor collection is a separately approved consequential action even if its artifact is read-only on the endpoint.
- Use Windows product/SKU plus release/build evidence to establish Windows 11 support. Never use the shared Windows 10/11 kernel 10.0 version as the classifier.
- Profiles resolve only modules explicitly named by the profile or CLI. Missing dependencies appear as blocked predecessors; resolution never adds or deploys them automatically.
- Define telemetry.limacharlie-wel as one endpoint-scoped module that references a separately pinned shared-platform collection template. A module has exactly one scope.
- Keep all tests under existing tests/unit, tests/contract, and tests/integration so pytest discovers them without changing testpaths.
- Preserve the policy-version fixture barrier: proposals created from fixtures remain unapprovable and all live apply paths stay disabled.

## 1. Clarify the design record and add hardening package scaffolding

Files:

- Modify docs/superpowers/specs/2026-09-16-modular-windows-hardening-package-design.md
- Add src/dfircmdcenter/hardening/__init__.py
- Add hardening/README.md
- Add hardening/modules/.gitkeep
- Add hardening/profiles/.gitkeep
- Add hardening/schemas/module.schema.json
- Add hardening/schemas/profile.schema.json
- Add hardening/schemas/evidence.schema.json

Work:

1. Clarify that telemetry.limacharlie-wel is endpoint scoped and references a pinned shared-platform template, rather than using a combined scope value.
2. State that hardening tests live in the repository-wide test directories.
3. Create the version-controlled hardening catalog root and explain the private-state boundary in hardening/README.md.
4. Define JSON schemas as distributable format contracts. Set additionalProperties to false for public records and include only non-secret fields.
5. Keep semantic and safety validation authoritative in Python; schemas provide interchange and editor validation, not a bypass around custom validation.

Acceptance:

- The design and catalog layout use one scope per module.
- No client mappings, secrets, target snapshots, receipts, or recovery keys are present under hardening/.
- All schema records reject unknown fields by contract.

## 2. Implement immutable catalog models and strict loading

Files:

- Add src/dfircmdcenter/hardening/models.py
- Add src/dfircmdcenter/hardening/catalog.py
- Add src/dfircmdcenter/hardening/errors.py
- Add tests/unit/test_hardening_catalog.py
- Add tests/contract/test_hardening_schemas.py
- Modify pyproject.toml and uv.lock only if a schema-validation dependency is selected

Work:

1. Define frozen records for ArtifactIdentity, ModuleDefinition, ModuleSelection, ProfileDefinition, ModuleScope, ModuleMode, SupportMatrix, ValidationRequirement, and RecoveryProcedure.
2. Reuse config.load_yaml for duplicate-key-safe YAML loading. Resolve only catalog-relative paths; reject traversal, symlink escape, missing artifacts, nonregular files, and artifact hashes that do not match.
3. Enforce strict module IDs, semantic versions, supported mode lists, one scope, valid dependency references, valid incompatibilities, non-empty recovery text, and SHA-256 artifact identities with origin, version, and review date.
4. Enforce a single structured profile-selection format:

~~~
module: defense.asr
version: 1.0.0
mode: audit
~~~

5. Reject secret-shaped keys, terminal controls, unsupported schema versions, duplicate module/version records, duplicate profile selections, unpinned module references, and fixture-only artifacts marked deployment-ready.
6. Deep-freeze nested catalog material before computing digests.

Tests:

- Valid module/profile load and deterministic digest.
- Duplicate YAML key, unknown field, invalid semantic version, bad digest, missing artifact, symlink/traversal path, duplicate module, unsupported mode, and secret-shaped field rejection.
- Profile cannot reference a tenant module or an unavailable module version.
- Loaded structures are immutable and preserve no mutable caller references.

## 3. Add Windows 11 preflight, evidence, and identity normalization

Files:

- Add src/dfircmdcenter/hardening/identity.py
- Add src/dfircmdcenter/hardening/preflight.py
- Add src/dfircmdcenter/hardening/evidence.py
- Add hardening/fixtures/windows11-home/preflight.yaml
- Add hardening/fixtures/windows11-pro/preflight.yaml
- Add tests/unit/test_hardening_preflight.py
- Add tests/unit/test_hardening_identity.py

Work:

1. Define sanitized evidence records with provider, collection method, capture time, evidence digest, target binding, freshness, and source classification: fixture, manual attestation, or platform-derived.
2. Establish Action1 endpoint, LimaCharlie sensor, and Velociraptor client correlation from strong IDs. Treat hostname-only identity as ambiguous.
3. Normalize Windows product name, client SKU, edition, release, build, Secure Boot, TPM, supported feature availability, Defender/firewall health, software inventory status, and backup readiness.
4. Require product/client evidence plus a supported Windows 11 release/build. Missing, contradictory, stale, target-mismatched, or future-dated evidence produces blocked or unknown status.
5. Model manual attestations separately. Device Encryption and recovery readiness may be attested, but recovery keys are never read or stored.
6. Consume existing evidence only. Do not invoke Action1, LimaCharlie, or Velociraptor collection APIs.

Tests:

- Windows 10, Windows Server, unsupported Windows 11 build, unknown SKU, and unavailable Home-edition feature are rejected or blocked as appropriate.
- Ambiguous identities, stale/future timestamps, mismatched target bindings, and unsupported capability evidence block planning.
- Manual attestation cannot contain secret values or substitute for required platform evidence.

## 4. Implement explicit selection and dependency resolution

Files:

- Add src/dfircmdcenter/hardening/resolver.py
- Add src/dfircmdcenter/hardening/planning.py
- Add tests/unit/test_hardening_resolver.py
- Add tests/unit/test_hardening_planning.py

Work:

1. Resolve selections from one optional profile plus explicitly named modules. Deduplicate only identical module/version/mode selections; reject conflicts.
2. Validate dependency graph cycles, module incompatibilities, mode conflicts, support-matrix mismatch, and tenant/shared-platform action smuggling.
3. Keep selected modules separate from missing predecessor requirements. Display every missing predecessor as blocked; never expand it into a selected, ready, or approved action.
4. Treat a dependency as satisfied only when fresh evidence confirms a verified result for the exact target and immutable module/configuration inputs. A selected predecessor is not already satisfied.
5. Keep identity/availability preflight outside the dependency graph so telemetry modules and endpoint-health verification do not form an artificial cycle.
6. Return an immutable plan with a canonical plan digest and per-item state: ready-for-proposal, verification-only, blocked, unsupported, deferred, or needs-manual-evidence.
7. Do not produce a bulk approval or batch apply object.

Tests:

- Independent module selection without a profile.
- Deterministic profile resolution and order.
- Missing predecessor remains unselected and blocked.
- Cycles, incompatible modes, duplicate conflicting selection, unsupported build, tenant action smuggling, shared artifact creation, stale predecessor, partial predecessor, and unknown predecessor rejection.
- Plan digest changes when any module, artifact, policy, profile, evidence, or mode changes.

## 5. Convert ready module actions into existing proposals

Files:

- Add src/dfircmdcenter/hardening/proposals.py
- Add src/dfircmdcenter/hardening/action1.py
- Modify src/dfircmdcenter/commands.py
- Add tests/unit/test_hardening_proposals.py
- Add tests/integration/test_hardening_cli.py

Work:

1. Build one immutable Proposal per ready, consequential endpoint module. Use Platform.ACTION1 and a module-specific operation name; do not add a separate hardening platform.
2. Bind the exact endpoint identity, module/version/mode, module and transitive artifact digests, selected non-secret deployment settings, preflight evidence, approval-policy digest, platform-contract digest, prerequisite receipt digests, verification definition digest, before state, expected effects, and recovery text.
3. Use a short expiration consistent with existing Action1 proposals. A change to an artifact, validation rule, policy, platform contract, or prerequisite receipt invalidates the proposal digest.
4. Keep fixture-derived proposals marked with a fixture policy version so proposal approval refuses them.
5. Generate dependent actionable proposals only after their prerequisites actually verify; do not create them based on predicted post-deployment state.
6. Reuse commands._save_proposal and the current ControlStore. Do not add a new store, approval command, execution engine, or live apply handler.
7. Add read-only CLI planning commands:

~~~
dfirctl hardening catalog validate
dfirctl hardening modules list
dfirctl hardening modules show MODULE@VERSION
dfirctl hardening profiles show PROFILE@VERSION
dfirctl hardening preflight --fixture NAME
dfirctl hardening plan --fixture NAME --profile PROFILE@VERSION
dfirctl hardening plan --fixture NAME --module MODULE@VERSION --mode MODE
dfirctl hardening proposal PLAN_ID --module MODULE@VERSION
~~~

Tests:

- A profile digest cannot authorize a module.
- Proposal binds target, module, version, mode, and all transitive immutable inputs.
- Sibling, target, version, and mode substitutions fail.
- Fixture proposal approval remains refused; apply remains disabled.
- A dependent module cannot generate a ready enforcement proposal before verified prerequisite evidence exists.
- CLI produces stable redacted output and performs no outbound requests.

## 6. Implement verification, promotion, and reconciliation evaluation

Files:

- Add src/dfircmdcenter/hardening/verification.py
- Add src/dfircmdcenter/hardening/promotion.py
- Add src/dfircmdcenter/hardening/receipts.py
- Add tests/unit/test_hardening_verification.py
- Add tests/unit/test_hardening_promotion.py

Work:

1. Evaluate Action1 operation outcome, configuration state, LimaCharlie telemetry, and correlated Velociraptor evidence against each module’s requirements.
2. Do not reuse action1.verify_deployment for general hardening modules; it is specifically for Velociraptor installation and does not provide the required terminal-operation semantics.
3. Mark contradictory evidence failed, missing evidence partial or unknown, and target/sensor/client mismatch failed or blocked according to the evidence contract.
4. Require an audit-to-enforce promotion record to include exact target/module/version/configuration, observation-window evidence, normal-workflow check, negative/safety test, and a fresh preflight. An event-free interval alone is insufficient.
5. Treat verify-only modules separately from deployment modules. Device-encryption verification records state plus recovery-readiness attestation only; backup verification requires successful restore evidence.
6. Reuse existing unknown-outcome reconciliation behavior. Never resubmit a deployment or create a profile-wide rollback. A rollback is a new exact target/module proposal.

Tests:

- Action1 says installed but terminal operation failed or pending.
- Wrong configuration state, wrong sensor/client, stale/pre-change telemetry, absent expected event channels, and missing normal-workflow evidence do not pass verification.
- Insufficient audit duration or mismatched module configuration blocks promotion.
- Unknown outcome remains non-retriable and blocks dependents.
- Encryption and backup verification fail without the required non-secret attestations/evidence.

## 7. Author release-eligible catalog content and optional profiles

Files:

- Add hardening/modules/validation.endpoint-health/module.yaml
- Add hardening/modules/telemetry.windows-audit/module.yaml
- Add hardening/modules/telemetry.powershell/module.yaml
- Add hardening/modules/telemetry.sysmon/module.yaml
- Add hardening/modules/telemetry.limacharlie-wel/module.yaml
- Add hardening/modules/defense.defender/module.yaml
- Add hardening/modules/defense.firewall/module.yaml
- Add hardening/modules/defense.asr/module.yaml
- Add hardening/modules/defense.controlled-folder-access/module.yaml
- Add hardening/modules/execution.app-control/module.yaml
- Add hardening/modules/data.device-encryption-verify/module.yaml
- Add hardening/modules/recovery.backup-verify/module.yaml
- Add matching artifacts.yaml, validation.yaml, and rollback.md files only where complete and hash-pinned
- Add hardening/profiles/test-audit.yaml
- Add hardening/profiles/family-standard.yaml
- Add tests/contract/test_hardening_catalog_content.py

Work:

1. Publish only complete catalog entries that have actual reviewed artifacts, action references, validation, recovery procedures, and support claims.
2. Mark non-ready catalog entries as deferred/unavailable with an explicit reason. They must not yield a valid deployment proposal.
3. Preserve the approved initial profile selections and keep App Control outside family-standard until an application inventory and allow rules are separately designed.
4. Do not invent vendor hashes, API surfaces, Action1 automation IDs, LimaCharlie collection definitions, Velociraptor artifact parameters, or Windows feature compatibility.
5. Record release eligibility separately from module existence. Fixture success does not mark a module Windows 11 tested, family-ready, or deployable.

Tests:

- Each published module has every required contract file and pinned immutable artifact identity.
- Each profile resolves only published, supported, non-tenant modules.
- Deferred modules are visible in planning output but cannot create a deployment proposal.
- No public catalog file contains credentials, private endpoint mappings, transcript contents, recovery keys, or raw evidence.

## 8. Integrate documentation, quality gates, and delivery checks

Files:

- Modify README.md
- Modify platforms/action1/README.md
- Modify platforms/limacharlie/README.md
- Modify platforms/velociraptor/README.md as needed for hardening verification boundaries
- Add tests/integration/test_hardening_workflows.py
- Modify .gitignore only if tests reveal an omitted private hardening path

Work:

1. Document how to validate catalog files, render profiles, inspect blocked prerequisites, and understand that an approved profile is not approval to apply modules.
2. Document the distinction between existing evidence reads and a separately approved fresh Velociraptor collection.
3. Add an end-to-end fixture workflow: validate catalog, preflight Windows 11 fixture, render test-audit, show blocked/deferred modules, create one fixture proposal, and verify that approval/apply remain refused.
4. Add contract tests that stub transports and fail if offline hardening commands attempt network I/O.
5. Ensure var/hardening is ignored and private-state path containment follows existing path safety rules.

Verification commands:

~~~
uv run pytest tests/unit/test_hardening_catalog.py tests/unit/test_hardening_preflight.py tests/unit/test_hardening_resolver.py tests/unit/test_hardening_proposals.py tests/unit/test_hardening_verification.py tests/unit/test_hardening_promotion.py
uv run pytest tests/contract/test_hardening_schemas.py tests/contract/test_hardening_catalog_content.py
uv run pytest tests/integration/test_hardening_cli.py tests/integration/test_hardening_workflows.py
uv run pytest
uv run ruff check .
uv run mypy src
~~~

## Completion criteria

The implementation is complete only when:

1. strict module/profile catalog validation passes offline;
2. Windows 11-only preflight rejects unsafe or ambiguous target evidence;
3. profile and manual selection render deterministic, non-bulk plans with visible blocked dependencies;
4. every actionable module proposal is exact, immutable, individually approval-gated, and fixture proposals remain unapprovable;
5. verification and promotion rules reject missing, stale, mismatched, or insufficient evidence;
6. no live platform mutation, Velociraptor tasking, or network call is possible through the new offline hardening commands;
7. full pytest, Ruff, and strict mypy pass; and
8. any future test-ring or production deployment is handled as a new scoped proposal with fresh approval.
