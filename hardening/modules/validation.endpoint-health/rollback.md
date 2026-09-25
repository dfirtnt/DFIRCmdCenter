# validation.endpoint-health recovery

This module changes no endpoint state and therefore has no rollback action. Do not
create or run an uninstall script for it.

If collection fails or produces ambiguous output, retain the Action1 outcome and
reconcile the failure read-only. Do not change Secure Boot, TPM, antivirus, firewall,
Memory Integrity, or management-agent services as part of this module.

Any exported raw Action1 result is private endpoint evidence. Keep it under ignored,
restricted `var/` state and remove it only through a separately approved retention
decision.
