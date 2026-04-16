# Scope Comparison

## pidtrail vs strace

- `strace` is excellent for single-process syscall debugging.
- `pidtrail` aims at a tighter security-focused timeline with process, file, and network metadata plus JSONL/report outputs.
- `pidtrail` is narrower in syscall coverage than `strace`.

## pidtrail vs auditd

- `auditd` is broader and policy-driven at the host level.
- `pidtrail` is scoped to an attached PID, process name, or launched command and is easier to use for focused investigations.

## pidtrail vs eCapture

- eCapture targets deeper protocol and plaintext extraction scenarios.
- `pidtrail` does not claim plaintext TLS visibility.
- `pidtrail` focuses on maintainable process/file/network metadata timelines.

