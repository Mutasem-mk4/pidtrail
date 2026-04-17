pkgname=pidtrail
pkgver=0.2.1
pkgrel=1
pkgdesc="Linux process-scoped runtime investigator for process, file, and network timelines"
arch=('x86_64' 'aarch64')
# No public upstream project URL exists yet.
url=""
license=('MIT')
depends=()
makedepends=('go')
# Local review tarball generated from a local git tag via packaging/make-local-release.sh.
source=("${pkgname}-${pkgver}.tar.gz")
sha256sums=('817dd67c2fc574c762fa377fa0246832e3136ae54b908feabddc92b4d7294629')

build() {
  cd "${srcdir}/${pkgname}-${pkgver}"
  export CGO_ENABLED=0
  export GOFLAGS="-buildmode=pie -mod=vendor -trimpath -buildvcs=false"
  go build -ldflags "-X github.com/pidtrail/pidtrail/internal/version.Version=${pkgver} -X github.com/pidtrail/pidtrail/internal/version.Commit=arch" -o pidtrail ./cmd/pidtrail
}

check() {
  cd "${srcdir}/${pkgname}-${pkgver}"
  export CGO_ENABLED=0
  export GOFLAGS="-mod=vendor -trimpath -buildvcs=false"
  go test ./...
}

package() {
  cd "${srcdir}/${pkgname}-${pkgver}"
  install -Dm0755 pidtrail "${pkgdir}/usr/bin/pidtrail"
  install -Dm0644 man/pidtrail.1 "${pkgdir}/usr/share/man/man1/pidtrail.1"
  install -Dm0644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
  install -Dm0644 README.md "${pkgdir}/usr/share/doc/${pkgname}/README.md"
  install -Dm0644 docs/architecture.md "${pkgdir}/usr/share/doc/${pkgname}/architecture.md"
  install -Dm0644 docs/support-matrix.md "${pkgdir}/usr/share/doc/${pkgname}/support-matrix.md"
  install -Dm0644 docs/security-model.md "${pkgdir}/usr/share/doc/${pkgname}/security-model.md"
  install -Dm0644 completions/pidtrail.bash "${pkgdir}/usr/share/bash-completion/completions/pidtrail"
  install -Dm0644 completions/pidtrail.zsh "${pkgdir}/usr/share/zsh/site-functions/_pidtrail"
  install -Dm0644 completions/pidtrail.fish "${pkgdir}/usr/share/fish/vendor_completions.d/pidtrail.fish"
}
