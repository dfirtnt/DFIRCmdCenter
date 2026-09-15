# Action1 runbook

The Action1 adapter is aimed at one exact automation, organization, endpoint, package,
and version. OAuth client credentials stay outside this repository. Status output must
never include token responses, authorization headers, or a client identifier paired
with secret material.

Deployment proposals pin the upstream installer hash, repackaged MSI hash, client
configuration hash, package and automation IDs, deployment settings, and a strong
Action1-to-Velociraptor endpoint correlation. Matching hostnames alone do not establish
identity.

The personal MSI may produce `0x800B0100` because it has no publisher signature. Keep
that warning visible. It is neither a failed download nor evidence that the installer
is trusted. Verification requires both the exact installed Velociraptor version and a
fresh check-in from the strongly correlated Velociraptor client.

Writes never retry automatically. A timeout after transmission becomes `unknown`; use
read-only Action1 deployment status and Velociraptor check-in state to reconcile it.
Removal or redeployment is a new proposal and approval.

