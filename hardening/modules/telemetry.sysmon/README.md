# telemetry.sysmon 1.0.0

This is an offline-staged Windows 11 x64 endpoint module for Microsoft Sysmon
15.22 with Olaf Hartong's balanced configuration at commit
`a5072591e173b7f7a9fe518ebd5c10e5313ef6f8`. It is not uploaded, approved for
deployment, validated on Windows 11, or release-eligible.

The module is intentionally initial-install only. It refuses Windows 10,
Windows Server, non-x64 systems, and any pre-existing Sysmon installation that
is not owned by this exact module. An exact rerun becomes a no-op only after the
ownership state, binary, signature, service, driver, and latest configuration
hash all agree.

## Private package assembly

Do not commit or redistribute the Microsoft binary through this repository.
Use `artifacts.yaml` as the immutable bill of materials:

1. Obtain the pinned Microsoft source ZIP and verify its SHA-256.
2. Extract only the pinned `Sysmon64.exe` and verify its SHA-256.
3. Obtain the pinned Olaf `sysmonconfig.xml` commit and verify its SHA-256.
4. Place those two files and the tracked Install and Uninstall scripts at the
   root of a flat ZIP.
5. Verify the exact member set and the deployment-bundle SHA-256 in
   `artifacts.yaml` before a separately approved private Action1 upload.

The earlier `v2` ZIP is retained only as source provenance. It does not contain
this module's Windows-client guard or ownership-aware rollback and must not be
treated as the canonical 1.0.0 bundle.

## Deployment and verification boundary

Installation, verifier upload, endpoint execution, rollback, and any
LimaCharlie configuration are separate consequential actions. The verifier is
parameterless and read-only. It emits only bounded status labels and hashes; it
does not emit hostnames, usernames, addresses, service paths, or event bodies.

Local Action1 success does not prove centralized logging. Release promotion
also requires fresh matching events from the correlated LimaCharlie sensor and
continuing Velociraptor health.

Sources:

- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Olaf Hartong Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
