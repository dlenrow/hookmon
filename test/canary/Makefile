# Makefile for canary eBPF test programs
# Requires: clang, llvm-strip, bpftool (for vmlinux.h), Go with cilium/ebpf

CLANG ?= clang
STRIP ?= llvm-strip
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Generate vmlinux.h from running kernel if not present
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile eBPF C programs to .o files
hello_bpf.o: hello_bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I. -c $< -o $@
	$(STRIP) -g $@

net_monitor.o: net_monitor.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I. -c $< -o $@
	$(STRIP) -g $@

hello_bpf_v2.o: hello_bpf_v2.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I. -c $< -o $@
	$(STRIP) -g $@

# Build the Go loader
load_canary: load_canary.go
	CGO_ENABLED=0 go build -o $@ $<

# bpftime attack simulation canaries
bpftime_sim: bpftime_sim.c
	$(CC) -o $@ $< -lrt

libfake_hook.so: fake_hook.c
	$(CC) -shared -fPIC -o $@ $<

# Build everything
.PHONY: all
all: hello_bpf.o net_monitor.o hello_bpf_v2.o load_canary bpftime_sim libfake_hook.so

# Hash all compiled programs (for reference in whitelist entries)
.PHONY: hashes
hashes: hello_bpf.o net_monitor.o hello_bpf_v2.o
	@echo "=== BPF bytecode hashes ==="
	@printf "hello_bpf.o:    sha256:"; sha256sum hello_bpf.o | cut -d' ' -f1
	@printf "net_monitor.o:  sha256:"; sha256sum net_monitor.o | cut -d' ' -f1
	@printf "hello_bpf_v2.o: sha256:"; sha256sum hello_bpf_v2.o | cut -d' ' -f1

# Run each canary (must run as root)
.PHONY: run-hello
run-hello: hello_bpf.o load_canary
	sudo ./load_canary hello_bpf.o syscalls sys_enter_getpid hello_count

.PHONY: run-netmon
run-netmon: net_monitor.o load_canary
	sudo ./load_canary net_monitor.o syscalls sys_enter_connect net_count

.PHONY: run-hello-v2
run-hello-v2: hello_bpf_v2.o load_canary
	sudo ./load_canary hello_bpf_v2.o syscalls sys_enter_getpid hello_count_v2

# Run bpftime simulation (must run as root)
.PHONY: run-bpftime
run-bpftime: bpftime_sim libfake_hook.so
	sudo ./bpftime_sim $(CURDIR)/libfake_hook.so /bin/true

.PHONY: clean
clean:
	rm -f *.o load_canary bpftime_sim libfake_hook.so vmlinux.h
