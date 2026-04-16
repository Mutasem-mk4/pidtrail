# Release Checklist

1. Run `gofmt -w cmd internal examples`.
2. Run `go test -mod=vendor ./...`.
3. Run `go vet -mod=vendor ./...`.
4. On Linux, validate:
   `sudo ./pidtrail --pid <pid>`
   `sudo ./pidtrail --process <name>`
   `sudo ./pidtrail --report-dir report -- /usr/bin/true`
5. Build Debian and Arch packages with distro toolchains.
6. Verify `docs/support-matrix.md` and `README.md` still match actual behavior.
7. Create or update a git tag for the release.
8. Generate the local review tarball with `packaging/make-local-release.sh 0.2.1`.
9. Validate the tag, tarball contents, and package checksum chain with `packaging/check-local-release.sh 0.2.1`.
10. On Linux, run `sudo sh packaging/linux-smoke.sh`.
11. Update the `PKGBUILD` and `.SRCINFO` checksum from that tarball if the release contents changed.
