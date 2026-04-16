# ADR 0003: No background daemon in v1

## Status

Accepted

## Decision

`pidtrail` remains a foreground CLI for v1. The process-scoped target model does not yet justify a resident daemon.

## Rationale

- easier review for distro maintainers
- smaller attack surface
- no service management requirements
- fewer install and removal side effects
