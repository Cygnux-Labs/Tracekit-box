# Tracekit Box. `make` builds the host binary for this machine and the guest for linux/arm64 and linux/amd64.
GO        ?= go
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
GOOS      ?= $(shell $(GO) env GOOS)
GOARCH    ?= $(shell $(GO) env GOARCH)
BIN       := bin
FUZZTIME  ?= 60s

.PHONY: all build guest host linux test race lint fuzz runs e2e clean

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

# every fuzz target (package:Target) for FUZZTIME each, one after another: each runs even when one before it fails,
# and the recipe fails if any did, or does not exist, naming them. A failing input is saved under its package's testdata/fuzz (`go test
# ./...` runs the saved inputs and seeds, so add it there once fixed). FuzzParsePatchVsGit needs git.
FUZZ_TARGETS := proto:FuzzReadFrame proto:FuzzChunkWriter agentrpc:FuzzClientReplies agentchannel:FuzzReadAgentFrame \
	agentchannel:FuzzAgentFields agentchannel:FuzzRegisterFrame tracekit:FuzzShellQuote image:FuzzDebugfsQuote \
	image:FuzzFixups config:FuzzParse config:FuzzParseSecretFlag daemon:FuzzParsePatch daemon:FuzzParsePatchVsGit \
	egress:FuzzForward egress:FuzzRedactReader egress:FuzzAddrForms egress:FuzzHostText egress:FuzzClientHello
fuzz:
	@failed=; for t in $(FUZZ_TARGETS); do \
		echo "$(GO) test -run='^$$' -fuzz='^$${t#*:}$$' -fuzztime=$(FUZZTIME) ./internal/$${t%%:*}"; \
		if ! $(GO) test -list "^$${t#*:}\$$" ./internal/$${t%%:*} | grep -qx "$${t#*:}"; then \
			echo "no fuzz target $${t#*:} in ./internal/$${t%%:*}"; failed="$$failed $$t"; continue; fi; \
		$(GO) test -run='^$$' -fuzz="^$${t#*:}\$$" -fuzztime=$(FUZZTIME) ./internal/$${t%%:*} || failed="$$failed $$t"; \
	done; if [ -n "$$failed" ]; then echo "fuzz failed:$$failed"; exit 1; fi

# Verified Runs: verify every signed run in runs/ (and recipes/, once it exists) with the Tracekit 1.4.2 CLI and rewrite
# the table in its README.md from the verified records (see runs/README.md). CI runs it with -check.
runs:
	$(GO) run ./cmd/tkbox-runs runs
	@if [ -d recipes ]; then $(GO) run ./cmd/tkbox-runs recipes; fi

# end-to-end on a Linux host with /dev/kvm, mkfs.ext4 and a running Tracekit 1.4.2 signer (see docs/development.md)
e2e: build
	TKBOX_BIN=$(abspath $(BIN)) $(GO) test -tags e2e -count=1 -timeout 30m -v ./e2e/...

clean:
	rm -rf $(BIN)
