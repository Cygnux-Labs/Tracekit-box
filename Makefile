# Tracekit Box. `make` builds the host binary for this machine and the guest for linux/arm64 and linux/amd64.
GO        ?= go
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
GOOS      ?= $(shell $(GO) env GOOS)
GOARCH    ?= $(shell $(GO) env GOARCH)
BIN       := bin
FUZZTIME  ?= 60s

.PHONY: all build guest host linux test race lint fuzz e2e clean

all: build

build: host guest

# the host binary for this machine (on macOS it is the CLI only: boxes need a Linux host with KVM)
host:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/tkbox ./cmd/tkbox

# static guest agents, one per architecture; tkbox looks for them next to its own binary
guest:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/tkbox-guest-linux-arm64 ./cmd/tkbox-guest
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/tkbox-guest-linux-amd64 ./cmd/tkbox-guest

# Linux host binaries for both architectures (release / Lima)
linux: guest
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/tkbox-linux-arm64 ./cmd/tkbox
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/tkbox-linux-amd64 ./cmd/tkbox

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

lint:
	@test -z "$$(gofmt -l cmd internal e2e 2>/dev/null)" || (echo "gofmt needed:"; gofmt -l cmd internal e2e; exit 1)
	$(GO) vet ./...
	GOOS=linux $(GO) vet ./...

# every fuzz target for FUZZTIME each, one after another; a failing input is saved under its package's testdata/fuzz
# (`go test ./...` runs the saved inputs and seeds, so add it there once fixed). FuzzParsePatchVsGit needs git.
fuzz:
	$(GO) test -run='^$$' -fuzz='^FuzzParse$$' -fuzztime=$(FUZZTIME) ./internal/config
	$(GO) test -run='^$$' -fuzz='^FuzzParseSecretFlag$$' -fuzztime=$(FUZZTIME) ./internal/config
	$(GO) test -run='^$$' -fuzz='^FuzzParsePatch$$' -fuzztime=$(FUZZTIME) ./internal/daemon
	$(GO) test -run='^$$' -fuzz='^FuzzParsePatchVsGit$$' -fuzztime=$(FUZZTIME) ./internal/daemon
	$(GO) test -run='^$$' -fuzz='^FuzzForward$$' -fuzztime=$(FUZZTIME) ./internal/egress
	$(GO) test -run='^$$' -fuzz='^FuzzRedactReader$$' -fuzztime=$(FUZZTIME) ./internal/egress
	$(GO) test -run='^$$' -fuzz='^FuzzAddrForms$$' -fuzztime=$(FUZZTIME) ./internal/egress
	$(GO) test -run='^$$' -fuzz='^FuzzHostText$$' -fuzztime=$(FUZZTIME) ./internal/egress
	$(GO) test -run='^$$' -fuzz='^FuzzClientHello$$' -fuzztime=$(FUZZTIME) ./internal/egress

# end-to-end on a Linux host with /dev/kvm, mkfs.ext4 and a running Tracekit 1.4.2 signer (see docs/development.md)
e2e: build
	TKBOX_BIN=$(abspath $(BIN)) $(GO) test -tags e2e -count=1 -timeout 30m -v ./e2e/...

clean:
	rm -rf $(BIN)
