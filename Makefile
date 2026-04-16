PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1
DOCDIR ?= $(PREFIX)/share/doc/pidtrail
LICENSEDIR ?= $(PREFIX)/share/licenses/pidtrail
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || printf dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf unknown)
RELEASE_VERSION ?= $(shell sed -n 's/^pkgver=//p' PKGBUILD 2>/dev/null || printf $(VERSION))

.PHONY: build cross test fmt lint verify release-local check-local-release linux-smoke clean install

build:
	go build -mod=vendor -trimpath -buildvcs=false -ldflags "-X github.com/pidtrail/pidtrail/internal/version.Version=$(VERSION) -X github.com/pidtrail/pidtrail/internal/version.Commit=$(COMMIT)" -o pidtrail ./cmd/pidtrail

cross:
	GOOS=linux GOARCH=amd64 go build -mod=vendor -trimpath -buildvcs=false ./cmd/pidtrail
	GOOS=linux GOARCH=arm64 go build -mod=vendor -trimpath -buildvcs=false ./cmd/pidtrail

test:
	go test -mod=vendor ./...

fmt:
	gofmt -w cmd internal examples

lint:
	go vet -mod=vendor ./...

verify: fmt test lint cross

release-local:
	./packaging/make-local-release.sh $(RELEASE_VERSION)

check-local-release:
	./packaging/check-local-release.sh $(RELEASE_VERSION)

linux-smoke:
	./packaging/linux-smoke.sh

clean:
	rm -f pidtrail coverage.out

install: build
	install -Dm0755 pidtrail $(DESTDIR)$(BINDIR)/pidtrail
	install -Dm0644 man/pidtrail.1 $(DESTDIR)$(MANDIR)/pidtrail.1
	install -Dm0644 LICENSE $(DESTDIR)$(LICENSEDIR)/LICENSE
	install -Dm0644 README.md $(DESTDIR)$(DOCDIR)/README.md
