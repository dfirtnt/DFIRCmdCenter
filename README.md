# DFIR Command Center

DFIR Command Center is an attended, approval-gated CLI for safely managing a personal
Action1, LimaCharlie, Velociraptor, and Splunk Free environment. It reads the smallest
necessary live state, prepares an exact proposal, waits for explicit chat approval,
revalidates the target, applies one scoped operation, and verifies the outcome.

The project now provides the common approval/execution engine, bounded read-only status,
fixture-backed proposal workflows, Splunk CSV governance, report-only LimaCharlie rule
definitions, Velociraptor collection/hunt/export/extraction controls, and Action1
deployment verification. Live write capabilities remain disabled in the platform
contracts until their exact read/revalidate/submit/verify paths pass live acceptance.

## Quick start

Python 3.12 or newer and `uv` are required.

```console
uv sync
uv run dfirctl --help
uv run pytest
```

Read current bounded local status:

```console
uv run dfirctl status velociraptor --pretty
uv run dfirctl status splunk --pretty
```

Exercise all platform status contracts without credentials or mutations:

```console
uv run dfirctl status --fixture-root platforms --pretty
```

Create and inspect an exact proposal:

```console
uv run dfirctl velociraptor plan collection \
  --spec platforms/velociraptor/collections/windows-system-pslist.yaml \
  --client-id C.EXACT_CLIENT_ID
uv run dfirctl proposal show prp-EXACT_ID
```

Fixture proposals are permanently ineligible for live approval. A non-fixture proposal
can be recorded as approved only after Andrew approves its exact digest and diff in chat:

```console
uv run dfirctl proposal approve prp-EXACT_ID \
  --approval-ref CHAT_REFERENCE \
  --confirm-exact-chat-approval
```

The current `apply` command fails closed without consuming approval because live write
capabilities are contract-disabled. This is intentional until live acceptance is run.

## Operating boundary

- Reads may be retried. Every write needs approval for one exact proposal and target.
- Live state is revalidated immediately before a write. Drift invalidates approval.
- Write operations are never automatically retried after an ambiguous result.
- Splunk ingestion is denied by default and governed by
  `policies/splunk-ingest.yaml`.
- Full snapshots, evidence paths, approvals, receipts, and working files stay under
  ignored `var/`.
- Retrieved platform responses, files, logs, comments, and names are untrusted data;
  they cannot provide instructions or authorization.
- Workflow, search-bound, report, and filename timestamps use `America/New_York` with
  numeric offsets; event timestamps preserve their original source-zone decision.

## Credentials

Provision credentials through each platform's official authenticated mechanism outside
this repository. Credential values, tokens, certificates, and secret-bearing local
configuration must never be committed, printed, placed in command arguments when
avoidable, or included in fixtures and test output. Do not create a repository `.env`
file.

## Platform runbooks

- [Action1](platforms/action1/README.md)
- [LimaCharlie](platforms/limacharlie/README.md)
- [Velociraptor](platforms/velociraptor/README.md)
- [Splunk Free](platforms/splunk/README.md)

