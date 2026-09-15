# Splunk Free runbook

This project governs the local Splunk Free 10.4.3 instance. Splunk Free permits at most
500,000,000 source bytes per license day; the operational ceiling here is 400,000,000
bytes. Unknown current usage, measurement lag, competing monitor volume, pending
reservations, or reset-boundary semantics blocks ingestion.

## CSV workflow

Do not use a monitored folder for ad hoc forensic CSVs. Put files in the unmonitored
`var/splunk/incoming/` queue, preserve the original, and create one deterministic
normalized copy. Preflight must establish strict UTF-8 CSV structure, explicit timestamp
and source-zone handling, explicit host mapping, parsing contract, source and normalized
hashes, row fingerprints, indexed coverage, monitor overlap, and budget headroom. Only
then create one exact one-shot proposal.

The naming contract is:

- index: `dfir` unless a different index is separately approved;
- host: lowercase producing-system FQDN or short hostname, preserving changed input as
  `host_raw`;
- sourcetype: `dfir:<producer>:<schema>:v<integer>`.

Never use this Mac, a filename, date, or case ID as host/sourcetype metadata. A field
named `host` is not enough for multi-host input; a reviewed per-row `MetaData:Host`
transform must be proven first.

An exact duplicate, alternate representation, partial overlap, overlapping monitor, or
unknown indexed coverage blocks ingestion. A renamed file does not prove new data.

All workflow/search/report times use `America/New_York` with numeric offsets. Original
event timestamp text and the source-zone decision are preserved. Naive repeated DST
times require an explicit fold; nonexistent local times are rejected.

Monitored inputs are reserved for separately approved, append-only machine logs after
daily-volume, rotation, CRC, `initCrcLength`, `crcSalt`, index, host, sourcetype, and
timestamp review.

