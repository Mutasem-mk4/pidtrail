PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1
DOCDIR ?= $(PREFIX)/share/doc/pidtrail
LICENSEDIR ?= $(PREFIX)/share/licenses/pidtrail
VERSION ?= dev
COMMIT ?= unknown

.PHONY: build test fmt lint clean install

build:
	go build -mod=vendor -trimpath -buildvcs=false -ldflags "-X github.com/pidtrail/pidtrail/internal/version.Version=$(VERSION) -X github.com/pidtrail/pidtrail/internal/version.Commit=$(COMMIT)" -o pidtrail ./cmd/pidtrail

test:
	go test -mod=vendor ./...

fmt:
	gofmt -w cmd internal examples

lint:
	go vet -mod=vendor ./...

clean:
	rm -f pidtrail coverage.out

install: build
	install -Dm0755 pidtrail $(DESTDIR)$(BINDIR)/pidtrail
	install -Dm0644 man/pidtrail.1 $(DESTDIR)$(MANDIR)/pidtrail.1
	install -Dm0644 LICENSE $(DESTDIR)$(LICENSEDIR)/LICENSE
	install -Dm0644 README.md $(DESTDIR)$(DOCDIR)/README.md

