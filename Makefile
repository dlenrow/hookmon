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

# eBPF objects embedded by agent/sensors/embed.go (linux only). Built from the
# host kernel's BTF; dlopen_monitor.c uses per-arch PT_REGS, so objects are
# host-arch specific.
SENSORS_DIR := agent/sensors
BPF_SRCS    := $(wildcard $(SENSORS_DIR)/*.c)
BPF_OBJS    := $(BPF_SRCS:.c=.o)
BPF_ARCH    := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
CLANG       ?= clang
LLVM_STRIP  ?= llvm-strip
BPFTOOL     ?= bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

# Targets that compile agent/sensors for linux need the eBPF objects first.
TARGET_OS := $(or $(GOOS),$(shell uname -s | tr '[:upper:]' '[:lower:]'))
ifeq ($(TARGET_OS),linux)
BPF_DEPS := bpf
endif

.PHONY: build-all build-bus build-agent build-server build-cli build-collector build-dlopen-probe build-dashboard build-canaries build-canaries-noebpf
.PHONY: bpf generate test test-unit test-registry test-collector test-integration test-e2e test-e2e-full e2e-deploy smoketest lint clean ci
.PHONY: package-deb package-rpm docker-agent docker-server
.PHONY: appliance-server appliance-qcow2 appliance-vhd appliance-ova appliance-compose

## Build targets

build-all: build-bus build-agent build-server build-cli build-collector build-dlopen-probe

build-bus: $(BPF_DEPS)
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/hookmon-bus ./cmd/hookmon-bus

build-collector:
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/hookmon-collector ./cmd/hookmon-collector

# C helper the bus runs to fire the dlopen uprobe (the bus is Go and does not call dlopen itself).
# The bus looks for it next to its own binary unless dlopen_probe_path is set.
build-dlopen-probe:
	@mkdir -p $(BIN_DIR)
	$(CC) -O2 -Wall -o $(BIN_DIR)/hookmon-dlopen-probe agent/probe/dlopen_probe.c -ldl

build-agent: $(BPF_DEPS)
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

bpf: $(BPF_OBJS)

$(SENSORS_DIR)/vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp
	mv $@.tmp $@

$(SENSORS_DIR)/%.o: $(SENSORS_DIR)/%.c $(SENSORS_DIR)/vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -I$(SENSORS_DIR) -c $< -o $@
	$(LLVM_STRIP) -g $@

## Testing

test: $(BPF_DEPS)
	go test ./...

test-unit: $(BPF_DEPS)
	go test -race -count=1 ./agent/ ./pkg/... ./server/policy/... ./server/connectors/... ./server/ingestion/... ./agent/config/... ./agent/sensors/... ./agent/transport/... ./agent/registry/... ./agent/observability/...

test-registry:
	go test -race -count=1 ./agent/registry/...

test-collector:
	go test -race -count=1 ./cmd/hookmon-collector/...

smoketest: $(BPF_DEPS)
	go test -v -count=1 ./test/smoketest/...

test-integration:
	go test -tags integration -count=1 ./test/integration/...

build-canaries:
	$(MAKE) -C test/canary all

build-canaries-noebpf:
	$(MAKE) -C test/canary canaries-noebpf

# e2e tests run as root through sudo, which drops the environment; these
# settings are passed through when set (see docs/theory-of-operations.md).
E2E_ENV := $(foreach v,HOOKMON_STATUS_PORT HOOKMON_LOKI_URL HOOKMON_E2E_LONG HOOKMON_E2E_IDLE_DURATION HOOKMON_E2E_REINSTALL_PKG,$(if $($(v)),$(v)=$($(v))))

e2e-deploy: build-bus build-dlopen-probe build-canaries
	@echo "==> Deploying canaries and bus to /tmp for e2e..."
	@mkdir -p /tmp/canary/bin
	cp $(BIN_DIR)/hookmon-bus /tmp/hookmon-bus
	cp $(BIN_DIR)/hookmon-dlopen-probe /tmp/hookmon-dlopen-probe
	cp test/canary/bin/* /tmp/canary/bin/ 2>/dev/null || true
	cp test/canary/*.o /tmp/canary/ 2>/dev/null || true
	cp test/canary/*.sh /tmp/canary/

test-e2e: e2e-deploy
	sudo env "PATH=$$PATH" $(E2E_ENV) go test -tags e2e -v -count=1 -timeout 300s ./test/e2e/...

# Full-path e2e (fix plan step 7h): a BPF canary through a root bus (not
# console mode), enrollment, gRPC, hookmon-server, PostgreSQL, policy, a
# webhook connector and the WebSocket feed. Starts PostgreSQL in a container
# (pinned by digest, data in tmpfs, published on a random localhost port),
# builds the server, runs the test and removes the container, also on
# failure. Needs docker and passwordless sudo, besides what test-e2e needs.
# E2E_FULL_RUN=. runs the whole e2e suite against that stack instead (the
# SIEM test also needs the alpine image it pulls).
E2E_PG_IMAGE ?= postgres:16.15-alpine3.24@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
E2E_FULL_RUN ?= TestFullPath
test-e2e-full: e2e-deploy build-server
	@set -eu; \
	name="hookmon-e2e-pg-$$$$"; \
	pw=$$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n'); \
	trap 'docker rm -f "$$name" >/dev/null 2>&1 || true' EXIT; \
	echo "==> Starting PostgreSQL ($$name)"; \
	docker run -d --name "$$name" -e POSTGRES_PASSWORD="$$pw" -p 127.0.0.1::5432 \
		--tmpfs /var/lib/postgresql/data:rw,size=512m $(E2E_PG_IMAGE) >/dev/null; \
	ready=; for i in $$(seq 60); do \
		if docker exec "$$name" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then ready=1; break; fi; \
		sleep 1; \
	done; \
	if [ -z "$$ready" ]; then docker logs "$$name"; echo "PostgreSQL did not become ready"; exit 1; fi; \
	port=$$(docker port "$$name" 5432/tcp | head -n1 | sed 's/.*://'); \
	sudo env "PATH=$$PATH" $(E2E_ENV) \
		HOOKMON_TEST_PG_DSN="postgres://postgres:$$pw@127.0.0.1:$$port/postgres?sslmode=disable" \
		HOOKMON_SERVER_BIN="$(CURDIR)/$(BIN_DIR)/hookmon-server" \
		go test -tags e2e -v -count=1 -timeout 300s -run '$(E2E_FULL_RUN)' ./test/e2e/...

lint:
	golangci-lint run ./...

## CI (local equivalent of GitHub Actions)

ci: build-all test-unit
	go vet ./...
	@echo "==> CI checks passed"

## Packaging

# hookmon-bus packages for this host's architecture (Linux only): the eBPF
# objects first, then the dlopen helper with $(CC), then the static bus and
# the package (scripts/build-agent.sh; needs dpkg-deb or rpmbuild).
package-deb: $(BPF_DEPS) build-dlopen-probe
	VERSION=$(VERSION) COMMIT=$(COMMIT) DATE=$(DATE) ./scripts/build-agent.sh deb

package-rpm: $(BPF_DEPS) build-dlopen-probe
	VERSION=$(VERSION) COMMIT=$(COMMIT) DATE=$(DATE) ./scripts/build-agent.sh rpm

docker-agent:
	docker build -f deploy/docker/Dockerfile.agent --build-arg VERSION=$(VERSION) -t hookmon-bus:$(VERSION) .

docker-server:
	docker build -f deploy/docker/Dockerfile.server --build-arg VERSION=$(VERSION) -t hookmon-server:$(VERSION) .

## Appliance

# hookmon-server for the appliance image and the Ansible appliance role
# (appliance/ansible): linux/amd64 whatever the build host.
APPLIANCE_SERVER := $(BIN_DIR)/linux-amd64/hookmon-server
appliance-server:
	@mkdir -p $(dir $(APPLIANCE_SERVER))
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(APPLIANCE_SERVER) ./cmd/hookmon-server

# QCOW2 image in appliance/packer/output, built from this tree. Needs packer,
# qemu and KVM, so a Linux build host. -force replaces an earlier build.
appliance-qcow2: appliance-server build-dashboard
	cd appliance/packer && packer init hookmon.pkr.hcl && packer build -force hookmon.pkr.hcl

# VHD (Hyper-V) and OVA (VMware), converted from that qcow2: run
# make appliance-qcow2 first. Need qemu-img. There is no ISO image.
appliance-vhd:
	appliance/packer/convert.sh vhd $(VERSION)

appliance-ova:
	appliance/packer/convert.sh ova $(VERSION)

# Compose appliance: builds the server and collector images and starts the
# stack. Run deploy/appliance/hookmon-init.sh --mode compose first, with
# --out-dir $(APPLIANCE_CONFIG_DIR).
APPLIANCE_CONFIG_DIR ?= /etc/hookmon
appliance-compose:
	HOOKMON_CONFIG_DIR=$(APPLIANCE_CONFIG_DIR) docker compose -f deploy/appliance/docker-compose.yml up -d --build --wait

## Cleanup

clean:
	rm -rf $(BIN_DIR)
	rm -rf dashboard/dist
	rm -f $(BPF_OBJS)
	$(MAKE) -C test/canary clean
	go clean -cache -testcache
