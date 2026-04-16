# Linux Validation

This workspace cannot perform live Linux tracing verification because it runs on Windows.

Use the Linux smoke harness on a real Linux host:

```sh
sudo sh packaging/linux-smoke.sh
```

What it checks:

- `pidtrail --diagnose` writes a report bundle on Linux
- launched-command mode captures process, file, and network events
- PID mode captures process, file, and network events
- process-name mode captures process, file, and network events
- loopback-only traffic is sufficient; no external network is required

Expected result:

- the script exits `0`
- it prints `linux smoke passed`
- each report bundle contains `events.jsonl` and `summary.json`

If it fails, inspect the generated logs printed by the script and then check:

- the kernel exposes the required tracepoints
- the process has enough privilege to load eBPF programs and attach tracepoints
- loopback networking works on `127.0.0.1:18080`
