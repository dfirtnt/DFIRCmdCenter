# Modular Windows Hardening Package Design

Date: 2026-09-16
Status: Approved in chat; awaiting review of this written specification. Implementation and endpoint deployment are not authorized by this document.
Related baseline: [Family Windows Hardening Baseline](../../windows-home-family-hardening-baseline.md)

## Purpose

Build a reusable, fully modular hardening package system for newly onboarded personal and family Windows 11 endpoints. The system will let an operator select individual hardening modules or a saved profile, review the exact plan, and deploy each module through Action1 only after a scoped approval.

LimaCharlie provides endpoint detection and centralized Windows Event Log telemetry. Velociraptor provides endpoint identity validation, targeted post-deployment checks, and incident-response collection. The package system does not create a new EDR, RMM, or evidence datastore.

## Scope

Version one supports:

- Windows 11 test machines
- parents' Windows 11 endpoints
- a small number of immediate-family Windows 11 endpoints
- Action1, LimaCharlie, and Velociraptor as the managed platform set

The earlier Windows 10 Enterprise test machine is outside version one's supported target matrix. It may support limited compatibility experiments, but it cannot establish Windows 11 package acceptance.

Version one excludes:

- business, domain-joined, Intune-managed, or multi-tenant clients
- automated LimaCharlie response actions such as isolation, blocking, process termination, or remote tasking
- unattended Action1 remote-control access
- continuous Velociraptor log shipping
- malware or honeypot devices; they require their own isolation and research-device design
- tenant-wide Action1 and LimaCharlie changes from an endpoint profile
- storage of client IDs, recovery keys, credentials, API material, or full endpoint snapshots in version-controlled files

## Design goals

1. Make each control independently selectable, versioned, testable, verifiable, and recoverable.
2. Retain profiles as optional, immutable saved selections of pinned modules.
3. Make every dependency visible before deployment; no profile or module may silently deploy another module.
4. Preserve the command center's exact-proposal, fresh-state, one-time-approval, and no-automatic-retry boundaries.
5. Use audit-to-enforce promotion for disruptive controls.
6. Produce evidence that confirms intended configuration and actual endpoint telemetry rather than inferring success from a deployment submission.
7. Keep private client facts and secret-bearing data outside repository files.

## Security invariants

- Each module proposal names one exact target, module version, mode, action, and verification procedure.
- A dependency is displayed as a required predecessor and must be separately selected and approved; it is never silently applied.
- A client profile is a saved selection, not an authorization artifact. It cannot override module gates, validation requirements, scopes, or approvals.
- Endpoint profiles cannot invoke tenant-scoped controls.
- Audit and enforce modes are distinct state transitions. Enforce mode requires fresh target state and retained audit evidence from that endpoint.
- Module artifacts have immutable identity: pinned version, origin, hash, and review date. A release label, mutable branch, or download URL alone is insufficient.
- Success requires an Action1 outcome plus the module's declared LimaCharlie and/or Velociraptor verification evidence.
- A failed or ambiguous action halts that module. It does not trigger automatic retries, broad rollback, or progression of dependent enforcement controls.
- No deployment script accepts credentials, recovery keys, API tokens, or secret-bearing configuration through repository files or command-line arguments.

## Architecture

### Scopes

| Scope | Purpose | Examples | Profile eligibility |
| --- | --- | --- | --- |
| endpoint | Controls on one Windows endpoint | Sysmon, audit policy, Defender, firewall, ASR, Controlled Folder Access, App Control | Allowed |
| shared-platform | Reusable platform artifacts referenced by endpoint modules | Action1 package definition, LimaCharlie WEL template, detection-rule pack, Velociraptor validation artifact | Referenced by version only |
| tenant | Organization-wide platform setting | Action1 remote-control defaults, LimaCharlie organization metadata and retention settings | Prohibited |

A profile can reference endpoint modules and shared-platform artifact versions. It cannot contain a tenant action or conceal a tenant setting behind an endpoint module.

### Repository layout

~~~
hardening/
  modules/
    telemetry.windows-audit/
      module.yaml
      artifacts.yaml
      validation.yaml
      rollback.md
    telemetry.powershell/
    telemetry.sysmon/
    telemetry.limacharlie-wel/
    defense.defender/
    defense.firewall/
    defense.asr/
    defense.controlled-folder-access/
    execution.app-control/
    data.device-encryption-verify/
    recovery.backup-verify/
    validation.endpoint-health/
  profiles/
    test-audit.yaml
    family-standard.yaml
  schemas/
    module.schema.json
    profile.schema.json
  fixtures/
    windows11-home/
    windows11-pro/
  tests/
    unit/
    contract/
    integration/
~~~

Client-specific records, module receipts, endpoint mappings, full snapshots, and approval state remain under ignored restricted private state. Public module definitions contain only non-secret identifiers, hashes, policy parameters, and verification expectations.

### Module contract

Each module must declare:

~~~
module ID and semantic version
scope: endpoint, shared-platform, or tenant
supported Windows editions and build range
required predecessor modules and incompatible modules
mode support: observe, audit, enforce, verify-only
immutable artifact identities: origin, version, SHA-256, review date
non-secret Action1 deployment action reference
LimaCharlie telemetry and alert expectations
Velociraptor validation artifact and parameters
rollback or recovery procedure
success, failure, and ambiguous-outcome criteria
~~~

A module may require a predecessor, but the rendered plan must show it separately. The system rejects circular dependencies, an unpinned artifact, an unsupported Windows build, an undeclared mode, and a profile reference to an unavailable module version.

### Profiles

Profiles are optional saved selections that pin module versions and modes. They are convenience manifests, not deployment commands.

~~~
profile: family-standard
version: 1.0.0
modules:
  - telemetry.windows-audit@1.0.0
  - telemetry.powershell@1.0.0
  - telemetry.sysmon@1.0.0
  - telemetry.limacharlie-wel@1.0.0
  - defense.defender@1.0.0
  - defense.firewall@1.0.0
  - defense.asr@1.0.0
    mode: audit
  - defense.controlled-folder-access@1.0.0
    mode: audit
  - validation.endpoint-health@1.0.0
~~~

The initial profiles are:

| Profile | Use | Initial mode |
| --- | --- | --- |
| test-audit | Known-good Windows 11 test endpoint | Observability plus audit-only restrictive controls |
| family-standard | Parents and immediate-family Windows 11 endpoints | Same pinned selection; enforcement occurs through later individual promotion proposals |

App Control is intentionally not in the first family-standard profile. It is an independent module because its allow rules depend on a verified application inventory and it has the highest normal-use disruption risk.

## Initial module catalog

| Module | Scope | Initial mode | Key acceptance evidence |
| --- | --- | --- | --- |
| validation.endpoint-health | endpoint | verify-only | Strong Action1, LimaCharlie, and Velociraptor endpoint correlation |
| telemetry.windows-audit | endpoint | enforce | Expected Windows Security audit events, including process creation with command line |
| telemetry.powershell | endpoint | enforce | PowerShell 4103/4104 events; transcript path and ACL verified locally |
| telemetry.sysmon | endpoint | enforce | Pinned Sysmon/configuration hashes; running service; Sysmon Operational events received |
| telemetry.limacharlie-wel | endpoint/shared-platform | enforce | Required Windows channels arrive in LimaCharlie in real time |
| defense.defender | endpoint | audit then enforce where supported | Defender health, cloud protection, PUA policy, and tamper-protection confirmation |
| defense.firewall | endpoint | enforce | All profiles enabled; intended inbound policy and dropped-traffic logging verified |
| defense.asr | endpoint | audit | Audit events during an observation window; enforce only by separate proposal |
| defense.controlled-folder-access | endpoint | audit | Audit events and confirmed normal write workflows; enforce only by separate proposal |
| execution.app-control | endpoint | audit | Code Integrity/App Control audit events and approved-app inventory review |
| data.device-encryption-verify | endpoint | verify-only | Device Encryption state and separately retained recovery key confirmed |
| recovery.backup-verify | endpoint | verify-only | Successful restoration of representative documents and photos |

This catalog does not claim that all Windows 11 Home devices expose every advanced feature. Module preflight must record edition, build, hardware capability, and feature availability before a proposal is rendered.

## Onboarding and promotion flow

### 1. Read-only client onboarding

Collect the minimum decision-relevant state:

- exact Windows edition, release, build, Secure Boot, TPM, and supported platform protections
- installed software and required family workflows
- Defender, firewall, Device Encryption, and relevant service states
- strongly correlated Action1 endpoint, LimaCharlie sensor, and Velociraptor client identities
- backup readiness

No automation, policy, sensor, or endpoint configuration changes occur in this phase.

### 2. Render a plan

The operator selects a profile and optional individual modules. The command center resolves and displays exact module versions, dependencies, modes, artifacts, target, expected effects, rollback paths, and acceptance checks.

The rendered result is a collection of module proposals, not a bulk execution authorization. Each consequential module action receives an individual approval.

### 3. Establish observability

Apply telemetry and validation modules first:

1. Windows audit policy
2. PowerShell logging
3. Sysmon
4. LimaCharlie Windows Event Log collection
5. endpoint-health verification

Stop if required telemetry is absent, endpoint identity is ambiguous, or the result cannot be reconciled after a submitted Action1 action.

### 4. Apply protective modules in audit

Deploy Defender, firewall, ASR, Controlled Folder Access, and App Control according to their module gates. Restrictive modules begin in audit mode unless their module explicitly declares a safe enforce-only mode and target preflight confirms support.

### 5. Review and promote

Use the defined observation window, normal-workflow validation, LimaCharlie events, and Velociraptor checks to determine whether one module is ready for enforcement. Promotion is a fresh proposal that re-reads target state and preserves the audit evidence used for the decision.

### 6. Record outcome

Record a redacted module receipt containing the proposal digest, selected module/version/mode, target pseudonym or non-secret stable ID, action outcome, verification results, and rollback status. Ambiguous results stay unresolved until read-only reconciliation establishes the actual state.

## Verification and testing

### Static and fixture validation

- Validate module and profile schemas.
- Reject duplicate IDs, invalid semantic versions, unpinned artifacts, unsupported mode/scope combinations, and circular dependencies.
- Confirm profiles reference published module versions only.
- Confirm endpoint profiles contain no tenant-scoped module.
- Verify fixture data is sanitized and contains no private endpoint state or credentials.

### Platform contracts

- Validate Action1 deployment payload structure without submitting live actions.
- Validate LimaCharlie collection definitions and detection rules before proposing a platform change.
- Validate Velociraptor artifact names, parameters, exact client scope, and expected result classes.
- Confirm each module has an explicit rollback or recovery path.

### Windows 11 test-ring validation

A module reaches release eligibility only after it has been tested on a supported Windows 11 test endpoint. The test record must show:

- deployment outcome from Action1
- continuing Action1, LimaCharlie, and Velociraptor health
- the module's expected Windows and LimaCharlie telemetry
- normal browser, printing, backup, and family-application workflows where applicable
- the module's explicit negative or safety test
- safe rollback or recovery validation when the module modifies enforcement state

Examples of module-specific negative tests include:

- an ASR audit event from a safe test scenario
- a Controlled Folder Access blocked write after enforcement, while approved software continues to write
- a portable unapproved remote-access executable producing App Control evidence
- a tested Security log-clear or sensor-offline detection with report-only response

### Production validation

A family endpoint receives the same pinned modules only after its own preflight and proposal approval. A test-machine result demonstrates compatibility of a package version; it does not substitute for target-specific state, approval, or verification.

## Failure handling and rollback

- Treat an Action1 timeout after submission as an unknown outcome; never resubmit automatically.
- Reconcile unknown state using read-only Action1 status, correlated LimaCharlie telemetry, and Velociraptor checks.
- Stop the affected module and do not promote a dependent module when preconditions, health checks, or expected telemetry fail.
- Roll back only the exact module and target approved for rollback. Never use a profile-level rollback that could reverse independently validated protections.
- A module that cannot safely rollback must document a recovery procedure and require explicit acknowledgement in its proposal.

## Security boundaries

- LimaCharlie responses are report-only in version one.
- Action1 remote-control defaults and related organization-wide settings are tenant-scoped proposals, outside the onboarding profile system.
- PowerShell logging and transcripts are sensitive telemetry; the package must not put secrets into scripts, script arguments, output, or transcript destinations.
- Sysmon uses a reviewed, hash-pinned balanced configuration. Noise tuning is evidence-driven and never achieved with unbounded exclusions.
- App Control is the enforcement boundary for approved software and unapproved RMM tools. ASR provides behavioral prevention but is not treated as a software allowlist.
- Device Encryption and recovery-key handling require manual confirmation where Windows 11 Home does not expose a manageable encryption feature.
- Honeypot and malware systems will receive a separate design with isolation, credential, networking, evidence, and recovery boundaries before any shared module is considered.

## Non-goals and deferred decisions

- Implementing modules, Action1 automations, LimaCharlie configuration, or Velociraptor collections
- Creating or enabling automated response
- Defining business-client profiles
- Designing the honeypot profile
- Enabling or changing tenant-wide remote-support settings
- Creating App Control allow rules before endpoint software inventory is reviewed
- Centrally shipping PowerShell transcripts before retention, access, and collection are separately approved

## Acceptance criteria for implementation planning

Implementation planning may begin only when:

1. this specification is approved in chat;
2. the module catalog and profile semantics remain unchanged;
3. Windows 11 test endpoint availability is confirmed;
4. the Action1/LimaCharlie/Velociraptor interfaces needed for read-only preflight and verification are confirmed;
5. a phase-one module subset is selected; and
6. the plan preserves individual proposal and approval gates for every consequential action.

## Reference material

- [Family Windows Hardening Baseline](../../windows-home-family-hardening-baseline.md)
- [Microsoft Defender ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft App Control feature availability](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/feature-availability)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Olaf Hartong Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
- [LimaCharlie Windows Event Log ingestion](https://docs.limacharlie.io/2-sensors-deployment/tutorials/windows-event-logs/)
