#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <version>" >&2
  exit 1
fi

version="$1"
tag="v$version"
prefix="pidtrail-$version"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

fail() {
  echo "release check failed: $*" >&2
  exit 1
}

pkgbuild_version="$(sed -n 's/^pkgver=//p' PKGBUILD)"
srcinfo_source="$(sed -n 's/^[[:space:]]*source = //p' .SRCINFO)"
pkgbuild_sha="$(sed -n "s/^sha256sums=('\\([0-9a-f]*\\)')$/\\1/p" PKGBUILD)"
srcinfo_sha="$(sed -n 's/^[[:space:]]*sha256sums = //p' .SRCINFO)"
debian_version="$(sed -n '1s/^[^(]*(\([0-9][^)]*\)).*/\1/p' debian/changelog | sed 's/-[^-]*$//')"

[ -n "$pkgbuild_version" ] || fail "could not read pkgver from PKGBUILD"
[ -n "$srcinfo_source" ] || fail "could not read source from .SRCINFO"
[ -n "$pkgbuild_sha" ] || fail "could not read sha256 from PKGBUILD"
[ -n "$srcinfo_sha" ] || fail "could not read sha256 from .SRCINFO"
[ -n "$debian_version" ] || fail "could not read Debian upstream version"

[ "$pkgbuild_version" = "$version" ] || fail "PKGBUILD pkgver=$pkgbuild_version does not match $version"
[ "$srcinfo_source" = "$prefix.tar.gz" ] || fail ".SRCINFO source=$srcinfo_source does not match $prefix.tar.gz"
[ "$debian_version" = "$version" ] || fail "debian/changelog version=$debian_version does not match $version"
[ "$pkgbuild_sha" = "$srcinfo_sha" ] || fail "PKGBUILD and .SRCINFO sha256 mismatch"

git rev-parse --verify "$tag" >/dev/null 2>&1 || fail "missing git tag $tag"

checksum_line="$(./packaging/make-local-release.sh "$version" "$tmpdir/$prefix.tar.gz")"
actual_sha="$(printf '%s\n' "$checksum_line" | awk 'NR==1 { print $1 }')"
[ -n "$actual_sha" ] || fail "could not parse generated sha256"
[ "$actual_sha" = "$pkgbuild_sha" ] || fail "generated sha256 $actual_sha does not match PKGBUILD/.SRCINFO"

archive_listing="$tmpdir/listing.txt"
tar -tf "$tmpdir/$prefix.tar.gz" > "$archive_listing"
grep -qx "$prefix/" "$archive_listing" || fail "source tarball does not start with $prefix/"
if grep -Eq "^$prefix/(PKGBUILD|\\.SRCINFO)$" "$archive_listing"; then
  fail "source tarball unexpectedly contains PKGBUILD or .SRCINFO"
fi

printf 'local release metadata verified for %s\n' "$version"
