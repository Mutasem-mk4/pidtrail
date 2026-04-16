# Changelog

## 0.2.0

- Pivoted from `netray` to `pidtrail`
- Added process lifecycle tracing for exec, clone/fork-style creation, and exit
- Added file-open tracing for `openat` and `openat2`
- Retained network metadata tracing for connect, accept, and socket close
- Added launched-command mode and report bundles
- Reworked docs, man page, CI, and packaging around the narrower runtime-investigator scope

## 0.1.0

- Initial `netray` scaffold

