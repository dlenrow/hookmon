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

.PHONY: build-all build-bus build-agent build-server build-cli build-collector build-dashboard build-canaries
.PHONY: generate test test-unit test-registry test-collector test-integration test-e2e smoketest lint clean ci
.PHONY: package-deb package-rpm docker-agent docker-server
.PHONY: appliance-ova appliance-qcow2 appliance-iso

## Build targets

build-all: build-bus build-agent build-server build-cli build-collector

build-bus:
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/hookmon-bus ./cmd/hookmon-bus

build-collector:
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/hookmon-collector ./cmd/hookmon-collector

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

test-unit:
	go test -race -count=1 ./pkg/... ./server/policy/... ./server/connectors/... ./server/ingestion/... ./agent/config/... ./agent/sensors/... ./agent/transport/... ./agent/registry/... ./agent/observability/...

test-registry:
	go test -race -count=1 ./agent/registry/...

test-collector:
	go test -race -count=1 ./cmd/hookmon-collector/...

smoketest:
	go test -v -count=1 ./test/smoketest/...

test-integration:
	go test -tags integration -count=1 ./test/integration/...

build-canaries:
	$(MAKE) -C test/canary all

build-canaries-noebpf:
	$(MAKE) -C test/canary canaries-noebpf

test-e2e: build-bus build-canaries
	@echo "==> Deploying canaries and bus to /tmp for e2e..."
	@mkdir -p /tmp/canary/bin
	cp $(BIN_DIR)/hookmon-bus /tmp/hookmon-bus
	cp test/canary/bin/* /tmp/canary/bin/ 2>/dev/null || true
	cp test/canary/*.o /tmp/canary/ 2>/dev/null || true
	cp test/canary/*.sh /tmp/canary/
	sudo go test -tags e2e -v -count=1 -timeout 300s ./test/e2e/...

lint:
	golangci-lint run ./...

## CI (local equivalent of GitHub Actions)

ci: build-all test-unit
	go vet ./...
	@echo "==> CI checks passed"

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
	$(MAKE) -C test/canary clean
	go clean -cache -testcache
