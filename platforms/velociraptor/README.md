# Velociraptor runbook

The configured local binary is `/Users/starlord/.local/bin/velociraptor` and the pinned
server contract is 0.77.2 on Darwin arm64. The API configuration remains outside this
repository and its secret-bearing contents are never read into output.

Immediate collection and hunt proposals use exact client IDs. If a label is used for an
immediate operation, resolve it to an immutable reviewed client list and revalidate that
membership before submission. A standing label hunt is different: it must explicitly
state that matching future clients will also run.

Collection proposals pin artifact definitions, parameters, timeouts, row limits, upload
limits, expected tables, and expected upload classes. `FINISHED` and zero tool-error
markers are insufficient by themselves. Preserve the DFIRMedic helper meanings exactly:

- exit 0: no unavailable-tool marker was found;
- exit 1: at least one tool was unavailable;
- exit 2: the collection log was missing or malformed.

Supported flow/hunt downloads are the normal export path and export preparation is an
approved server operation. Output stays under `var/velociraptor/exports/`.

Datastore-derived extraction is limited to one exact finished client/flow and never
modifies the datastore. It requires a stable source inventory, fresh exclusive output
directory, pinned helper hash, decoded-path/collision/symlink/resource preflight, and
post-extraction inventory and truncation checks. Any uncertainty falls back to the
supported export path.

