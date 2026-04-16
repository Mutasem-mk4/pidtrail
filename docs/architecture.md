# Architecture

## Goal

`pidtrail` is a Linux-first runtime investigator that produces a process-scoped activity timeline.

## Data flow

1. The CLI resolves a scope from `--pid`, `--process`, or a launched command after `--`.
2. The Linux backend keeps a target PID set in an eBPF map.
3. eBPF tracepoints emit process, file, and network metadata for matching tasks.
4. User space enriches socket events from `/proc/<pid>/fd` and `/proc/<pid>/net/*`.
5. Output handlers render live events and optional report artifacts.

## Components

- `internal/config`: CLI options and validation
- `internal/event`: common event model
- `internal/output`: terminal, JSON, JSONL, and report writing
- `internal/report`: summary generation
- `internal/trace/linux`: Linux tracepoint backend
- `internal/procfs`: PID scans and socket enrichment

## Current capture surface

- Process events: `clone`/`fork`-style creation, `exec`, `exit`
- File events: `openat`, `openat2`
- Network events: `connect`, `accept`, `accept4`, `close` with best-effort socket enrichment

## Non-goals

- Plaintext TLS capture
- Packet content capture
- Universal system call tracing
- Packet sniffer replacement

