#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <version> [output-path]" >&2
  exit 1
fi

version="$1"
tag="v$version"
prefix="pidtrail-$version"
out="${2:-$prefix.tar.gz}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{ print $NF }'
    return 0
  fi
  echo "no sha256 tool found" >&2
  exit 1
}

git rev-parse --verify "$tag" >/dev/null
git archive --format=tar --prefix="$prefix/" "$tag" | tar -xf - -C "$tmpdir"

rm -f "$tmpdir/$prefix/PKGBUILD" "$tmpdir/$prefix/.SRCINFO"

mkdir -p "$(dirname "$out")"
tar -C "$tmpdir" --sort=name --owner=0 --group=0 --numeric-owner -cf - "$prefix" | gzip -n > "$out"
printf '%s  %s\n' "$(sha256 "$out")" "$out"
