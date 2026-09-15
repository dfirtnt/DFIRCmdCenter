# Governed Splunk sourcetypes

Reviewed parsing definitions belong here and use names shaped as
`dfir:<producer>:<schema>:v<integer>`.

Rendering a proposed `props.conf` or `transforms.conf` under ignored `var/` is a
local planning step. Copying configuration into
`/Users/starlord/splunk/etc/apps/dfircmdcenter/`, creating an index, or restarting
Splunk are separate consequential actions and each requires an exact approval.

Ad hoc forensic CSV files go through the unmonitored `var/splunk/incoming/`
queue and one-shot preflight. Do not point a monitor stanza at that directory.
Monitors are reserved for reviewed append-only machine logs.

