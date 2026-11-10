# Build and install wolverine.
#
#   make                  build bin/wolverine
#   make check            gofmt check, go vet and tests
#   sudo make install     install the binary, configuration and systemd service
#   sudo make uninstall   remove them (the configuration and state are kept)
#
# Run "make" as yourself first: "sudo make install" then only copies the
# files, without needing Go in root's PATH.
#
# Variables: PREFIX (/usr/local), SYSCONFDIR (/etc), DESTDIR (staging root
# for packaging; nothing is run on the system when it is set), GO (go),
# TAGS (e.g. TAGS=nosystemd to build without the systemd journal source).

GO         ?= go
TAGS       ?=
PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc
CONFDIR    ?= $(SYSCONFDIR)/wolverine
UNITDIR    ?= $(SYSCONFDIR)/systemd/system
SYSUSERSDIR ?= /usr/lib/sysusers.d
DESTDIR    ?=

BIN     := bin/wolverine
SOURCES := $(shell find cmd internal -name '*.go' -not -name '*_test.go') go.mod go.sum
GOFLAGS_BUILD := -trimpath $(if $(TAGS),-tags $(TAGS))

.PHONY: all build build-nosystemd test vet fmt check clean install uninstall

all: build

build: $(BIN)

# A file target: "sudo make install" does not rebuild when bin/wolverine is
# up to date.
$(BIN): $(SOURCES)
	@mkdir -p $(dir $@)
	$(GO) build $(GOFLAGS_BUILD) -o $@ ./cmd/wolverine

# Static binary without cgo nor the systemd-service source.
build-nosystemd:
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -tags nosystemd -o $(BIN) ./cmd/wolverine

test:
	$(GO) test $(if $(TAGS),-tags $(TAGS)) ./...

vet:
	$(GO) vet $(if $(TAGS),-tags $(TAGS)) ./...

fmt:
	gofmt -w cmd internal

check: vet test
	@out=$$(gofmt -l cmd internal); if [ -n "$$out" ]; then echo "not gofmt'ed:"; echo "$$out"; exit 1; fi

clean:
	rm -rf bin

install: $(BIN)
	install -D -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/wolverine
	@# Never overwrite an edited configuration or secrets file.
	@if [ -e $(DESTDIR)$(CONFDIR)/wolverine.yaml ]; then \
		install -m 0644 config/wolverine.yaml $(DESTDIR)$(CONFDIR)/wolverine.yaml.new; \
		echo "$(CONFDIR)/wolverine.yaml exists: kept, the new one is wolverine.yaml.new"; \
	else \
		install -D -m 0644 config/wolverine.yaml $(DESTDIR)$(CONFDIR)/wolverine.yaml; \
	fi
	@if [ ! -e $(DESTDIR)$(CONFDIR)/wolverine.env ]; then \
		install -m 0600 deploy/systemd/wolverine.env.example $(DESTDIR)$(CONFDIR)/wolverine.env; \
	fi
	@# Included configuration files: same rule, an existing file is kept and
	@# the new version gets a .new suffix (which wolverine does not read).
	install -d -m 0755 $(DESTDIR)$(CONFDIR)/rules.d
	@for f in config/rules.d/*.yaml config/rules.d/*.yml; do \
		[ -e "$$f" ] || continue; \
		dest=$(DESTDIR)$(CONFDIR)/rules.d/$$(basename "$$f"); \
		if [ -e "$$dest" ]; then \
			install -m 0644 "$$f" "$$dest.new"; \
			echo "$(CONFDIR)/rules.d/$$(basename "$$f") exists: kept, the new one is $$(basename "$$f").new"; \
		else \
			install -m 0644 "$$f" "$$dest"; \
		fi; \
	done
	install -D -m 0644 deploy/systemd/wolverine.sysusers $(DESTDIR)$(SYSUSERSDIR)/wolverine.conf
	@mkdir -p $(DESTDIR)$(UNITDIR)
	sed -e 's|/usr/local/bin/wolverine|$(BINDIR)/wolverine|g' \
	    -e 's|/etc/wolverine/|$(CONFDIR)/|g' \
	    deploy/systemd/wolverine.service > $(DESTDIR)$(UNITDIR)/wolverine.service
	chmod 0644 $(DESTDIR)$(UNITDIR)/wolverine.service
ifeq ($(DESTDIR),)
	systemd-sysusers $(SYSUSERSDIR)/wolverine.conf
	systemctl daemon-reload
	@echo
	@echo "Installed. Review $(CONFDIR)/wolverine.yaml (and $(CONFDIR)/wolverine.env), then:"
	@echo "  systemctl enable --now wolverine"
	@echo "  journalctl -u wolverine -f"
endif

uninstall:
ifeq ($(DESTDIR),)
	-systemctl disable --now wolverine
endif
	rm -f $(DESTDIR)$(BINDIR)/wolverine \
	      $(DESTDIR)$(UNITDIR)/wolverine.service \
	      $(DESTDIR)$(SYSUSERSDIR)/wolverine.conf
ifeq ($(DESTDIR),)
	systemctl daemon-reload
	@echo "Kept: $(CONFDIR) (configuration), /var/lib/wolverine (state) and the wolverine user."
endif
