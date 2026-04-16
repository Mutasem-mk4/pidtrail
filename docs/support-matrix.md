# Support Matrix

## Supported

- Linux only
- Intended targets: `amd64`, `arm64`
- PID targeting
- process-name targeting
- launched-command targeting
- process events: exec, clone/fork-style child creation, exit
- file events: `openat`, `openat2`
- network events: `connect`, `accept`, `accept4`, socket close metadata
- terminal output
- JSON and JSONL export
- report bundles with `events.jsonl` and `summary.json`

## Partial

- descendant tracking depends on clone/fork-style event visibility
- socket close events are emitted only when user-space enrichment can confirm the fd still resolves to a socket
- process-name targeting is refreshed from `/proc` and is therefore best-effort around short-lived processes
- this workspace has compile verification, not live Linux runtime verification
- a Linux smoke-validation harness exists in `packaging/linux-smoke.sh`, but it has not been executed in this workspace

## Unsupported

- plaintext TLS capture
- HTTP body capture
- HTTP/2 and HTTP/3 protocol decoding
- full packet capture
- Windows and macOS runtime support

## Runtime assumptions

- Linux tracepoints must be available
- eBPF program loading and tracepoint attach must be permitted
- `/proc` access must be sufficient for PID scans and socket enrichment
