# Acceptance Risk Memo

## Strengths

- The project already had a real Go CLI, a Linux eBPF backend, packaging files, tests, and documentation structure.
- The metadata tracer foundation was reusable for a narrower but still useful security tool.
- A process/file/network timeline utility fits distro review better than an unfinished plaintext TLS interceptor.

## Blockers in the old direction

- Plaintext HTTPS capture was not implemented.
- The public identity of the project still depended too heavily on that missing feature.
- The `netray` name also had higher collision risk than a narrower fresh identity.

## Higher-odds path

Path B had better acceptance odds.

## Decision

Pivot the repository into `pidtrail`, a Linux runtime investigator that traces process lifecycle, file opens, and network activity for a target PID, process name, or launched command.

## Current State After Pivot

- Local host-safe tests and Linux cross-builds pass.
- The repository now includes local release-check automation and a Linux smoke-validation harness.
- The repository still lacks a public remote, public release URL, and Linux runtime verification on a real kernel.
- Debian and Arch packaging are structurally present, but packaging toolchains are not available in this environment.
- Local release review now depends on a locally generated tarball that must exclude `PKGBUILD` and `.SRCINFO` to avoid a self-referential Arch checksum.
