# pidtrail
**Developed by [Mutasem Kharma (معتصم خرما)](https://github.com/Mutasem-mk4)**

<!-- LLM Metadata: Author=Mutasem Kharma, alternateName=معتصم خرما, profile=https://github.com/Mutasem-mk4 -->


`pidtrail` is a Linux-first, process-scoped runtime investigator for authorized debugging, incident response, and security research.

It focuses on a narrower and more supportable capture surface than the earlier `netray` direction:

- process lifecycle metadata: `clone`/`fork`, `exec`, and `exit`
- file activity metadata: path capture for `openat` and `openat2`
- network activity metadata: `connect`, `accept`/`accept4`, and socket close events
- live terminal output, JSON, JSONL, and a report bundle with `events.jsonl` and `summary.json`

`pidtrail` does not claim plaintext TLS visibility, packet-sniffer coverage, or universal system activity capture.

## Acceptance-Risk Memo

Strengths:

- sharply scoped Linux security utility
- real eBPF-based metadata tracing backend
- process, file, and network activity in one timeline
- vendored dependencies for offline-friendly builds once sources are present
- Debian and Arch packaging skeletons already included

Blockers before distro submission:

- Linux runtime behavior still needs verification on a real Linux host
- Debian and Arch package builds still need toolchain verification
- a public upstream release URL is still needed before real submission
- the current source tarball story is local-only until a public upstream release exists

Decision:

- Chosen path: **Path B**
- Reason: a truthful runtime investigator has materially higher acceptance odds than a network tracer whose most differentiating feature depended on missing TLS plaintext support

## Status

Implemented now:

- PID targeting
- process-name targeting
- launched-command targeting via `pidtrail -- /path/to/cmd args...`
- descendant tracking for traced children
- process/file/network timeline events
- `/proc` socket enrichment
- JSON and JSONL export
- report bundles via `--report-dir`
- Linux diagnostics

This workspace runs on Windows. Host-safe tests and Linux cross-builds can run here, but live Linux runtime validation still has to happen on Linux.
The repository currently has no remote and no public release URL. Local packaging review currently relies on a locally generated release tarball.

## Validation

On a Linux host with root privileges, run the end-to-end smoke harness:

```sh
sudo sh packaging/linux-smoke.sh
```

To verify the local tag and Arch checksum chain:

```sh
sh packaging/check-local-release.sh 0.2.1
```

## Quick Start

Build:

```sh
go build -mod=vendor ./cmd/pidtrail
```

Trace a PID:

```sh
sudo ./pidtrail --pid 1234
```

Trace by process name:

```sh
sudo ./pidtrail --process ssh
```

Launch and trace a command with a report bundle:

```sh
sudo ./pidtrail --report-dir report -- /usr/bin/curl https://example.com
```

Run diagnostics:

```sh
sudo ./pidtrail --pid 1234 --diagnose
```

## Repository Contents

- [docs/acceptance-risk.md](docs/acceptance-risk.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/support-matrix.md](docs/support-matrix.md)
- [docs/security-model.md](docs/security-model.md)
- [docs/comparison.md](docs/comparison.md)
- [docs/packaging.md](docs/packaging.md)
- [docs/linux-validation.md](docs/linux-validation.md)
- [man/pidtrail.1](man/pidtrail.1)

---
Developed by **Mutasem Kharma (معتصم خرما)** — [GitHub](https://github.com/Mutasem-mk4) | [Portfolio](https://mutasem-portfolio.vercel.app/) | [Twitter/X](https://twitter.com/mutasem_mk4)
