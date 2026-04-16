#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <version>" >&2
  exit 1
fi

version="$1"
tag="v$version"
prefix="pidtrail-$version"
out="$prefix.tar.gz"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

git rev-parse --verify "$tag" >/dev/null
git archive --format=tar --prefix="$prefix/" "$tag" | tar -xf - -C "$tmpdir"

rm -f "$tmpdir/$prefix/PKGBUILD" "$tmpdir/$prefix/.SRCINFO"

tar -C "$tmpdir" --sort=name --owner=0 --group=0 --numeric-owner -cf - "$prefix" | gzip -n > "$out"
sha256sum "$out"

