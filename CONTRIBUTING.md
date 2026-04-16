# Contributing

## Principles

- Prefer smaller truthful scope over larger unsupported claims.
- Keep the code reviewable and packaging-friendly.
- Preserve least-privilege defaults and clear failure modes.
- Avoid feature work that expands scope without tests or documentation.

## Development

Recommended checks:

```sh
gofmt -w cmd internal examples
go test -mod=vendor ./...
go vet -mod=vendor ./...
```

Linux validation should additionally cover:

- attach by PID
- attach by process name
- launched-command mode
- file-open events
- network events
- report bundle generation

