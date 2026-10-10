# Makefile for canary test programs
# Requires: clang, llvm-strip, bpftool (for vmlinux.h), Go with cilium/ebpf

CLANG ?= clang
STRIP ?= llvm-strip
CC ?= cc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Output directory
OUT := $(CURDIR)/bin

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

hello_bpf_mod.o: hello_bpf_mod.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I. -c $< -o $@
	$(STRIP) -g $@

raw_tp_canary.o: raw_tp_canary.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I. -c $< -o $@
	$(STRIP) -g $@

# Build the Go BPF loader
$(OUT)/load_canary: load_canary.go | $(OUT)
	CGO_ENABLED=0 go build -o $@ $<

# Loads N copies of one program and prints each kernel ID and tag
$(OUT)/bpf_tag_canary: bpf_tag_canary.go | $(OUT)
	CGO_ENABLED=0 go build -o $@ $<

# bpftime attack simulation
$(OUT)/bpftime_sim: bpftime_sim.c | $(OUT)
	$(CC) -o $@ $< -lrt

$(OUT)/libfake_hook.so: fake_hook.c | $(OUT)
	$(CC) -shared -fPIC -o $@ $<

# exec through execveat(AT_EMPTY_PATH) with LD_PRELOAD set
$(OUT)/execveat_canary: execveat_canary.c | $(OUT)
	$(CC) -o $@ $<

all canaries-noebpf: $(OUT)/execveat_canary

# Sensor-specific canaries
$(OUT)/dlopen_canary: dlopen_canary.c | $(OUT)
	$(CC) -o $@ $< -ldl

$(OUT)/ptrace_canary: ptrace_canary.c | $(OUT)
	$(CC) -o $@ $<

$(OUT)/shm_canary: shm_canary.c | $(OUT)
	$(CC) -o $@ $< -lrt

$(OUT)/shm_openat2_canary: shm_openat2_canary.c | $(OUT)
	$(CC) -o $@ $<

$(OUT)/ptrace_regs_canary: ptrace_regs_canary.c | $(OUT)
	$(CC) -o $@ $<

$(OUT)/test_rpath: test_rpath.c | $(OUT)
	$(CC) -o $@ $< -Wl,-rpath,/tmp/evil

$(OUT)/test_rpath_origin: test_rpath.c | $(OUT)
	$(CC) -o $@ $< '-Wl,-rpath,$$ORIGIN/../lib'

# RUNPATH (not RPATH) $ORIGIN/../tmp: a library directory next to the binary.
# The e2e test runs it from a bin/ whose sibling tmp/ is world-writable.
$(OUT)/test_rpath_origin_tmp: test_rpath.c | $(OUT)
	$(CC) -o $@ $< '-Wl,--enable-new-dtags,-rpath,$$ORIGIN/../tmp'

$(OUT):
	mkdir -p $(OUT)

# Build everything
.PHONY: all
all: hello_bpf.o net_monitor.o hello_bpf_v2.o hello_bpf_mod.o raw_tp_canary.o \
     $(OUT)/load_canary $(OUT)/bpf_tag_canary $(OUT)/bpftime_sim $(OUT)/libfake_hook.so \
     $(OUT)/dlopen_canary $(OUT)/ptrace_canary $(OUT)/shm_canary \
     $(OUT)/shm_openat2_canary $(OUT)/ptrace_regs_canary \
     $(OUT)/test_rpath $(OUT)/test_rpath_origin $(OUT)/test_rpath_origin_tmp

# Build just the canaries that don't need eBPF toolchain
.PHONY: canaries-noebpf
canaries-noebpf: $(OUT)/bpftime_sim $(OUT)/libfake_hook.so \
                 $(OUT)/dlopen_canary $(OUT)/ptrace_canary $(OUT)/shm_canary \
                 $(OUT)/shm_openat2_canary $(OUT)/ptrace_regs_canary \
                 $(OUT)/test_rpath $(OUT)/test_rpath_origin $(OUT)/test_rpath_origin_tmp

# Hash all compiled BPF programs (for reference in allowlist entries)
.PHONY: hashes
hashes: hello_bpf.o net_monitor.o hello_bpf_v2.o
	@echo "=== BPF bytecode hashes ==="
	@printf "hello_bpf.o:    sha256:"; sha256sum hello_bpf.o | cut -d' ' -f1
	@printf "net_monitor.o:  sha256:"; sha256sum net_monitor.o | cut -d' ' -f1
	@printf "hello_bpf_v2.o: sha256:"; sha256sum hello_bpf_v2.o | cut -d' ' -f1

# Run individual canaries (must run as root)
.PHONY: run-hello run-netmon run-hello-v2 run-bpftime
run-hello: hello_bpf.o $(OUT)/load_canary
	sudo $(OUT)/load_canary hello_bpf.o syscalls sys_enter_getpid hello_count

run-netmon: net_monitor.o $(OUT)/load_canary
	sudo $(OUT)/load_canary net_monitor.o syscalls sys_enter_connect net_count

run-hello-v2: hello_bpf_v2.o $(OUT)/load_canary
	sudo $(OUT)/load_canary hello_bpf_v2.o syscalls sys_enter_getpid hello_count_v2

run-bpftime: $(OUT)/bpftime_sim $(OUT)/libfake_hook.so
	sudo $(OUT)/bpftime_sim $(OUT)/libfake_hook.so /bin/true

.PHONY: run-dlopen run-ptrace run-shm run-linker-config run-lib-integrity run-exec-injection run-rpath
run-dlopen: $(OUT)/dlopen_canary $(OUT)/libfake_hook.so
	sudo $(OUT)/dlopen_canary $(OUT)/libfake_hook.so

run-ptrace: $(OUT)/ptrace_canary
	sudo $(OUT)/ptrace_canary

run-shm: $(OUT)/shm_canary
	sudo $(OUT)/shm_canary

run-linker-config:
	sudo bash linker_config_canary.sh

run-lib-integrity: $(OUT)/libfake_hook.so
	sudo bash lib_integrity_canary.sh $(OUT)/libfake_hook.so

run-exec-injection: $(OUT)/libfake_hook.so
	bash exec_injection_canary.sh $(OUT)/libfake_hook.so

.PHONY: run-execveat
run-execveat: $(OUT)/execveat_canary $(OUT)/libfake_hook.so
	$(OUT)/execveat_canary $(OUT)/libfake_hook.so /bin/true

run-rpath: $(OUT)/test_rpath
	$(OUT)/test_rpath

.PHONY: clean
clean:
	rm -rf $(OUT) *.o vmlinux.h
