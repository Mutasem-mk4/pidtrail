# Security Model

## Intended use

`pidtrail` is for authorized runtime investigation of specific processes or launched commands.

## Least privilege

The current Linux backend is metadata-oriented, but it still needs privilege to:

- load and attach tracepoint eBPF programs
- inspect relevant `/proc` entries
- keep per-target state in eBPF maps

In practice, that usually means running as `root` unless the host has been prepared for narrower tracing privileges.

## Data minimization

- No packet payload capture
- No plaintext TLS capture
- File activity records path attempts for selected open syscalls, not file contents
- Network activity records metadata, not payloads

## Failure behavior

`pidtrail` should fail clearly on:

- unsupported platforms
- missing privileges
- missing tracepoints
- `/proc` access failures that prevent requested enrichment

## Privacy considerations

Even metadata can be sensitive. Operators should assume captured paths, command names, PIDs, and endpoints may contain confidential information.

