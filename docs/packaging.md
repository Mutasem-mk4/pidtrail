# Packaging Notes

## Debian-family targets

The repository ships a `debian/` directory as an upstream-maintained starting point.

Current packaging intent:

- `Rules-Requires-Root: no`
- no interactive maintainer scripts
- no capability-setting `postinst`
- vendored Go dependencies for offline builds once source is present
- meaningful DEP-8 smoke coverage

Because there is no public upstream URL yet, `debian/control` intentionally omits `Homepage`, `Vcs-Browser`, and `Vcs-Git` fields instead of inventing them.

## Arch-family targets

The repository ships `PKGBUILD` and `.SRCINFO`.

Current packaging intent:

- offline builds once the source tarball is present
- standard install paths
- hardening-friendly Go build flags
- binary, man page, docs, license, and completions installed

Because there is no public upstream URL yet, `PKGBUILD` currently leaves `url=""` and uses a local source tarball name only.
That is suitable for local review, not for public repository submission.

## Local-only source tarball story

Until a public upstream release exists, local Arch review should use a locally generated tarball built from a local git tag.

Important detail:

- the local tarball must exclude `PKGBUILD` and `.SRCINFO`

That avoids a self-referential checksum problem, since the Arch packaging recipe lives in the repository but should not be part of the source tarball it verifies.

Use [packaging/make-local-release.sh](../packaging/make-local-release.sh) after creating a local tag.
It generates the local review tarball directly from `git archive` while excluding `PKGBUILD` and `.SRCINFO`.
Then verify the tag, tarball contents, and Arch checksum metadata with [packaging/check-local-release.sh](../packaging/check-local-release.sh).

## Current gap

This workspace does not have `dpkg-buildpackage`, `lintian`, `autopkgtest`, or `makepkg`, so packaging structure was prepared but not toolchain-verified here.
