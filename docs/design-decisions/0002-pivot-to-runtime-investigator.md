# ADR 0002: Pivot away from TLS-dependent positioning

## Status

Accepted

## Decision

The repository pivots from `netray` to `pidtrail`, a runtime investigator built around process, file, and network metadata.

## Rationale

This improves acceptance odds by removing dependence on an unimplemented TLS plaintext feature.

