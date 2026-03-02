SHELL := /bin/bash
.DEFAULT_GOAL := build-all

# Version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -ldflags "-X github.com/dlenrow/hookmon/pkg/version.Version=$(VERSION) \
	-X github.com/dlenrow/hookmon/pkg/version.Commit=$(COMMIT) \
	-X github.com/dlenrow/hookmon/pkg/version.Date=$(DATE)"

# Output
BIN_DIR := bin

.PHONY: build-all build-agent build-server build-cli build-dashboard
.PHONY: generate test test-integration test-e2e lint clean
.PHONY: package-deb package-rpm docker-agent docker-server
.PHONY: appliance-ova appliance-qcow2 appliance-iso

## Build targets

build-all: build-agent build-server build-cli

build-agent:
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/hookmon-agent ./cmd/hookmon-agent

build-server:
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/hookmon-server ./cmd/hookmon-server

build-cli:
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/hookmon-cli ./cmd/hookmon-cli

build-dashboard:
	cd dashboard && npm ci && npm run build

## Code generation

generate:
	@echo "==> Generating eBPF and protobuf code..."
	./scripts/generate.sh

## Testing

test:
	go test ./...

test-integration:
	go test -tags integration -count=1 ./test/integration/...

test-e2e:
	go test -tags e2e -count=1 ./test/e2e/...

lint:
	golangci-lint run ./...

## Packaging

package-deb:
	@echo "Building Debian package..."
	./scripts/build-agent.sh deb

package-rpm:
	@echo "Building RPM package..."
	./scripts/build-agent.sh rpm

docker-agent:
	docker build -f deploy/docker/Dockerfile.agent -t hookmon-agent:$(VERSION) .

docker-server:
	docker build -f deploy/docker/Dockerfile.server -t hookmon-server:$(VERSION) .

## Appliance

appliance-ova:
	cd appliance/packer && packer build -only='*.vmware-iso' hookmon.pkr.hcl

appliance-qcow2:
	cd appliance/packer && packer build -only='*.qemu' hookmon.pkr.hcl

appliance-iso:
	./appliance/iso/build-iso.sh

## Cleanup

clean:
	rm -rf $(BIN_DIR)
	rm -rf dashboard/dist
	go clean -cache -testcache
