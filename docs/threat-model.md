# HookMon Threat Model

This document lists the ways code gets into a Linux process, and for each one which HookMon sensor covers it, or that none does. It ends with what HookMon itself trusts.

Status values:

- **Tested**: a sensor reports it, and a test shows that. The test is named; [claims.md](claims.md) records the runs.
- **Code reading**: the code handles it, but no test does it.
- **Partial**: some forms are covered and some are not. The details say which.
- **Not covered**: no sensor reports it.
- **Dropped**: a sensor sees it but does not report it, because it cannot be a stealth hook; the bus counts it. See [What the bus drops](#what-the-bus-drops).
- **Not applicable**: the mechanism does not affect that kind of process.

The tests ran on one host: Ubuntu 22.10, kernel 5.19, x86_64. Nothing here has been checked on arm64 or on other kernels.

## Coverage

| Way code enters a process | Sensor | Status | Evidence |
|---|---|---|---|
| eBPF program load, `bpf(BPF_PROG_LOAD)` | `bpf_syscall` | Tested | `TestSensor1_BPFSyscall_DetectLoad`, `TestSensor1_BPFSyscall_SameProgramSameTag`, `TestSensor1_BPFSyscall_ModifiedProgramNewTag` |
| eBPF attach through `bpf()`: `BPF_LINK_CREATE`, `BPF_RAW_TRACEPOINT_OPEN` | `bpf_syscall` | Tested | `TestSensor1_BPFSyscall_LinkCreateAttach`, `TestSensor1_BPFSyscall_RawTracepointAttach` |
| eBPF attach through `bpf(BPF_PROG_ATTACH)` | `bpf_syscall` | Code reading | |
| eBPF link retarget, `bpf(BPF_LINK_UPDATE)` | — | Not covered | |
| eBPF programs loaded before HookMon started | `bpf_syscall` inventory | Tested | `TestSensor1_BPFInventory_PreexistingProgram` |
| eBPF attach outside `bpf()`: perf `PERF_EVENT_IOC_SET_BPF`, netlink XDP and tc, `SO_ATTACH_BPF` | — | Not covered | The program's load is still reported, and the inventory lists it |
| Userspace eBPF (bpftime) | `shm_monitor`, `exec_injection` | Partial | Simulator only: `TestCombined_BpftimeAttackChain`, `TestSensor3_SHMMonitor_BpftimeDefaultName`, `TestSensor3_SHMMonitor_EnvRenamedIsBpftime`. The real runtime was not run. |
| `LD_PRELOAD` | `exec_injection` | Tested | `TestSensor2_ExecInjection_LDPreload`, `TestExecInj_PreloadAt100th`, `TestExecInj_Execveat`, `TestExecInj_ScanTruncated` |
| `LD_AUDIT`, `LD_DEBUG` | `exec_injection` | Tested | Root-only unit test `TestExecInjScanBoundary` |
| `LD_LIBRARY_PATH` with an entry a non-root user could fill (empty, relative, under `/tmp`, `/var/tmp`, `/dev/shm` or `/home`, missing, or writable by a non-root user or group) | `exec_injection` | Tested | `TestSignal_LibraryPathRiskyIsReported` |
| `LD_LIBRARY_PATH` of standard and root-only directories | — | Dropped | Counted as suppressed; see [What the bus drops](#what-the-bus-drops). `TestSignal_LibraryPathSafeIsSuppressed` |
| Other variables that make a process load code: `GCONV_PATH`, `PYTHONPATH`, `PERL5LIB`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS` and similar | — | Not covered | |
| `/etc/ld.so.preload` | `linker_config` | Tested | `TestLinkerConfig_PreloadOperations` (`cp`, `sed -i`, `mv`, `ln -sf`, `rm`) |
| `/etc/ld.so.conf.d/` | `linker_config` | Tested | `TestSensor5_LinkerConfig_WriteConfD` |
| `/etc/ld.so.conf` | `linker_config` | Code reading | |
| `/etc/ld.so.cache` | `linker_config` | Partial | No test writes it outside a package manager. A rewrite by `ldconfig` under a package manager is dropped. |
| Linker files changed by a package manager | — | Dropped | Counted as suppressed; see [What the bus drops](#what-the-bus-drops) |
| Linker files inside a container's own root filesystem | — | Not covered | Only the host's `/etc` is watched |
| `DT_RPATH` / `DT_RUNPATH` of the executed binary | `elf_rpath` | Tested | `TestSensor8_ElfRpath_OriginTmpCleanEnv`, `TestSensor8_ElfRpath_SuspiciousPath`, `TestRpathW_EmitOncePerBinaryVersion` |
| `DT_RUNPATH` of a shared library the binary loads | — | Not covered | Only the executable is analyzed |
| Library replaced in `/usr/lib`, `/usr/lib64`, `/lib`, `/lib64` | `lib_integrity` | Tested | `TestLibIntegrity_SoOperations`, `TestSensor7_LibIntegrity_WriteToUsrLib` |
| Library written there by a package manager | — | Dropped | Counted as suppressed. `TestLibIntegrity_AptReinstallIsSuppressed` |
| Library replaced anywhere else (`/usr/local/lib`, other `ld.so.conf` directories, `/opt`, RPATH directories, container images) | — | Not covered | |
| Library swapped by a bind mount or a mount namespace | — | Not covered | |
| Executable replaced on disk | — | Not covered | The exe hash on later events changes, but nothing alerts |
| `dlopen` in glibc, host and containers, of a library a non-root user could change | `dlopen_monitor` | Tested | `TestSensor4_DlopenMonitor_LoadLibrary`, `TestDlopenW_ContainerLibc`, `TestDlopenW_Dedupe`, `TestSignal_DlopenRootOnlyIsSuppressed` |
| `dlopen` of a library only root can change (the file, its directory and every directory above it) | — | Dropped | Counted as suppressed, judged in the process's own root. `TestSignal_DlopenRootOnlyIsSuppressed`, `TestDlopenW_ContainerLibc`. A library planted by root outside the watched library directories is therefore not reported; see [What the bus drops](#what-the-bus-drops) |
| `dlmopen` | — | Not covered | |
| `dlopen` in musl or in a static binary | — | Not covered | |
| ptrace attach: `PTRACE_ATTACH` | `ptrace_monitor` | Tested | `TestSensor6_PtraceMonitor_Attach`, `TestSensor6_PtraceMonitor_AttachTargetComm`, `TestSensor6_PtraceMonitor_TargetCommInPidNamespace` |
| ptrace attach: `PTRACE_SEIZE` | `ptrace_monitor` | Code reading | |
| ptrace attach: `PTRACE_TRACEME` | — | Not covered | The tracer's later writes are reported |
| ptrace memory writes: `PTRACE_POKETEXT`, `PTRACE_POKEDATA` | `ptrace_monitor` | Code reading | |
| ptrace register and USER-area writes: `PTRACE_SETREGS` (x86), `PTRACE_SETREGSET`, `PTRACE_POKEUSER` | `ptrace_monitor` | Tested | `TestSensor6_PtraceMonitor_RegisterWrites` |
| Other ptrace writes: `PTRACE_SETFPREGS`, `PTRACE_SETFPXREGS`, `PTRACE_SETSIGINFO`, `PTRACE_SET_THREAD_AREA`, arch-specific requests | — | Not covered | |
| ptrace reads and control: `PEEK*`, `GETREGS*`, `CONT`, `SYSCALL`, `SINGLESTEP`, `DETACH`, `INTERRUPT` | — | Not covered | These write no code or registers. Reads can leak secrets. |
| `process_vm_writev` | — | Not covered | Out of scope in the fix plan |
| Writes to `/proc/<pid>/mem` | — | Not covered | Out of scope in the fix plan |
| memfd and fileless exec (`memfd_create` + `fexecve` or `execveat`) | `exec_injection` | Partial | `LD_*` variables are still reported (`TestExecInj_Execveat` execs through a file descriptor). The fileless binary itself is not reported, and `elf_rpath` can't analyze `/dev/fd/N` once the process exits. |
| `dlopen` of a memfd (`/proc/self/fd/N`) | `dlopen_monitor` | Code reading | Reported with the `/proc/self/fd/N` path |
| Reflective loaders, shellcode, JIT: code mapped without `dlopen` or written to executable memory | — | Not covered | Out of scope in the fix plan |
| Shared memory in `/dev/shm` created with `open`/`openat`/`openat2` and `O_CREAT` (`shm_open`), with a bpftime or BPF name | `shm_monitor` | Tested | `TestSensor3_SHMMonitor_*` |
| Shared memory whose name and creator say nothing about BPF | — | Dropped | Counted as suppressed. `TestSensor3_SHMMonitor_GenericIsSuppressed` |
| Other shared memory: System V `shmget`, memfd, `creat()`, `O_TMPFILE` + `linkat`, relative or dirfd-relative opens, `/run/shm`, renames into `/dev/shm`, opens through io_uring | — | Not covered | |
| Kernel modules and livepatch (`init_module`, `finit_module`) | — | Not covered | |
| `binfmt_misc` interpreters | — | Not covered | |
| Static binaries | — | Not applicable | No dynamic linker, so `LD_*`, linker files and RPATH do nothing. `exec_injection` still reports `LD_*` variables. |
| musl | Several | Partial | See below |

## What the bus drops

HookMon reports what could be a stealth hook, not every use of a mechanism. Some events happen constantly on ordinary hosts and cannot be a hook someone planted: a browser's shared-memory segments, a package upgrade rewriting libraries, a daemon loading its plugins from a system directory. The bus drops these before they reach the server or Loki, and counts each one in `hookmon_events_suppressed_total{sensor,reason}` on its `/metrics`, so the volume stays visible.

| Sensor | Dropped | Reason label | Why it cannot be a stealth hook | What still covers it |
| --- | --- | --- | --- | --- |
| `shm_monitor` | A `/dev/shm` segment whose name has no BPF pattern and whose creator's environment does not name it as bpftime's | `no_bpf_pattern` | Shared memory is data, not code; HookMon watches it only for bpftime's segment. On a workstation, the browser alone creates about two segments a second | bpftime's own names, the `BPFTIME_GLOBAL_SHM_NAME` rename, and any name with `bpf` as a word are still reported. bpftime also needs `LD_PRELOAD` or ptrace, which are reported |
| `linker_config` | A write with a package manager in the writer's process ancestry (`ldconfig` after an install, a package's `ld.so.conf.d` file) | `package_manager` | It is a software update, not a change to how the linker is configured by someone else | Any other writer is CRITICAL. The baseline hash still moves, so the next reported change shows the package's version as its old hash |
| `lib_integrity` | A library written with a package manager in the writer's ancestry | `package_manager` | Same | Any other writer is ALERT |
| `dlopen_monitor` | A `dlopen` of a library that only root can change: the file, its directory and every directory above it, ranked as RPATH directories are (theory-of-operations), in the calling process's own root, so a container is judged in the container | `root_only_directory` | Programs load plugins from system directories all the time. Only root could have put the library there | A library in a directory a non-root user or group can write, under `/tmp`, `/var/tmp`, `/dev/shm` or `/home`, a world-writable or user-owned file, a relative path, `/proc/self/fd/N`, a missing directory, and anything the sensor cannot judge, are reported. Replacing a library in `/usr/lib`, `/usr/lib64`, `/lib` or `/lib64` is reported by `lib_integrity` |
| `exec_injection` | An `LD_LIBRARY_PATH` whose every entry is a standard library directory or a directory only root can write, judged in the new process's root | `safe_search_path` | It cannot lead the program to a library anyone but root planted | `LD_PRELOAD`, `LD_AUDIT` and `LD_DEBUG` are always reported. An `LD_LIBRARY_PATH` with any entry ranked MEDIUM or higher (empty, relative, a dangerous directory, a missing directory, one a non-root user or group can write) is reported, including containerd's `/opt/containerd/lib:`, whose empty entry is the working directory |

What this gives up:
- A library planted by root in a directory only root can write, outside the four watched library directories (`/usr/local/lib`, `/opt/<vendor>`, `/usr/libexec`), and then loaded with `dlopen`, is not reported by any sensor. Before this filter `dlopen_monitor` reported it at WARN.
- A package manager's writes are trusted. Malware run from a package's install script (`postinst`) has the package manager in its ancestry, so its linker and library writes are dropped too.
- `ldconfig` run by hand after a package install has no package manager in its ancestry, and its rewrite of `/etc/ld.so.cache` is still reported.

## Details

### eBPF

Every eBPF program is loaded with `bpf(BPF_PROG_LOAD)`. `bpf_syscall` reports each load as BPF_LOAD with the kernel's program tag, read from the kernel when the load returns. The tag is the same for every load of the same instructions on the same kernel, and changes when an instruction changes. Two programs with the same instructions and different program types share a tag.

`BPF_PROG_ATTACH`, `BPF_LINK_CREATE` and `BPF_RAW_TRACEPOINT_OPEN` are reported as BPF_ATTACH. `BPF_MAP_CREATE` is not reported; a map runs no code. Programs loaded before the bus started appear in the BPF_INVENTORY scan at startup, which repeats every 5 minutes.

Not covered:
- `BPF_LINK_UPDATE`, which swaps the program behind an existing link.
- Attaches that don't use `bpf()`: the perf `PERF_EVENT_IOC_SET_BPF` ioctl, netlink for XDP and tc, and `setsockopt(SO_ATTACH_BPF)`. The program still had to be loaded, so its load is reported and the inventory lists it. What is missed is where it was attached.
- Classic BPF (seccomp filters, `SO_ATTACH_FILTER`). It does not go through `bpf()`.

### Userspace eBPF (bpftime)

bpftime runs eBPF in userspace. It injects its runtime with `LD_PRELOAD` and talks to it through shared memory. Two sensors see that:
- `exec_injection` reports the `LD_PRELOAD`.
- `shm_monitor` reports the segment. A name containing `bpftime` (bpftime's default is `bpftime_maps_shm`), or one named by `BPFTIME_GLOBAL_SHM_NAME` in the creator's environment, is CRITICAL.

This was tested with `bpftime_sim`, a simulator, not with bpftime itself. A modified bpftime that picks some other segment name without that variable is classified by name: ALERT if it contains `bpf` as a word, and not reported otherwise. If a runtime injects into an already running process through ptrace, `ptrace_monitor` reports the ptrace requests it uses from the list above; that was not tested with bpftime.

### Environment variables

`exec_injection` attaches to `sched_process_exec`, which fires after every successful `execve` and `execveat`. It reads the new process's environment from the kernel's copy, the strings `ld.so` will read. It reports `LD_PRELOAD`, `LD_AUDIT` and `LD_DEBUG` always, and `LD_LIBRARY_PATH` when one of its entries ranks MEDIUM or higher as an RPATH entry would. ld.so splits the value at colons and semicolons, and an empty entry is the working directory. The entries are judged as the new process sees the filesystem; when that process and its parent have left the mount namespace of the exec, or a value cut short at 255 bytes can no longer be read in full from `/proc`, the variable is reported.

- On kernels with `bpf_loop` (5.17+) it reads up to 8192 chunks of 256 bytes; on older kernels, 512. If the scan stops early, it sends an event flagged `scan_truncated`.
- A value over 255 bytes is flagged `value_truncated`.
- An absolute `LD_PRELOAD` or `LD_AUDIT` path gets a `sha256:` hash. A bare library name does not.
- The sensor reads the environment whatever the libc, so it works for musl binaries too.

Not covered: other variables that make a process load code. glibc loads iconv modules from `GCONV_PATH`. Interpreters load code from their own variables: `PYTHONPATH`, `PYTHONSTARTUP`, `PERL5LIB`, `PERL5OPT`, `RUBYOPT`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`.

### Linker configuration

`linker_config` watches `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.cache` and the entries of `/etc/ld.so.conf.d/` with fanotify directory-entry events (Linux 5.9+). Writes, creates, deletes and renames over them are reported, with old and new hashes. A change is CRITICAL. A change with a package manager in the writer's process ancestry is not reported, only counted.

Not covered:
- A container's own `/etc/ld.so.preload` and `ld.so.conf`. Only the host's `/etc` is marked.
- musl's search path file (`/etc/ld-musl-<arch>.path`).
- Moving a file out of a watched directory (`FAN_MOVED_FROM` is not in the mask).
- A write through a hard link that lives outside the watched directories.

### RPATH and RUNPATH

`elf_rpath` attaches to `sched_process_exec` and analyzes the `DT_RPATH` and `DT_RUNPATH` of every executed binary, once per binary version. Entries are ranked by who can write the directory; a binary whose highest risk is MEDIUM or above raises an ELF_RPATH event. The ranking is in [theory-of-operations.md](theory-of-operations.md#class-7-rpathrunpath-abuse).

Not covered:
- The `DT_RUNPATH` of the shared libraries a binary loads. Only the executable is analyzed.
- Directories only root can write. They rank LOW and raise no event, by design.
- A binary whose process exited before the bus could resolve its path: relative paths outside the cwd, `/dev/fd/N` (fexecve, memfd), scripts (the interpreter is what loads), other mount namespaces, and names of 255 bytes or more.
- A library planted in an RPATH directory. `lib_integrity` watches only the standard directories.

### Library replacement on disk

`lib_integrity` watches `*.so` and `*.so.*` under `/usr/lib`, `/usr/lib64`, `/lib` and `/lib64`, every directory below them included. It hashes every library at startup in the background, and reports writes, creates, deletes and renames with old and new hashes. A change is ALERT. A change with a package manager in the writer's ancestry is not reported, only counted.

Not covered:
- Libraries anywhere else: `/usr/local/lib` and other `ld.so.conf` directories, `/opt`, RPATH directories, container image layers.
- A library swapped by a bind mount or in another mount namespace. No file is written.
- Executables. Replacing `/usr/bin/sshd` raises nothing. Later events from that binary carry a different exe hash.
- A file changed while the bus is down. At the next start, its new hash becomes the baseline.
- `FAN_MOVED_FROM` and hard-link writes, as for linker files.

### dlopen and dlmopen

`dlopen_monitor` puts a uprobe on the exported `dlopen` in every distinct glibc that any process has mapped, including containers that bring their own glibc. It rescans `/proc/*/maps` every 5 minutes and reports each (exe hash, library path) pair at most once an hour.

It reports a library only if someone other than root could have changed it. The library is found in the calling process's own root: a path as given, symlinks resolved there; a bare name by the file the process has mapped under that name, or else by every entry its `ld.so.cache` lists for it. The file and its directory are ranked as an RPATH entry would be. If only root can change the file, its directory and every directory above it, the dlopen is dropped and counted. Relative paths, `/proc/self/fd/N`, a bare name that is neither mapped nor cached, a deleted file and an unreadable path are reported.

Not covered:
- A library only root can change, outside the directories `lib_integrity` watches (see [What the bus drops](#what-the-bus-drops)).
- `dlmopen`.
- musl (Alpine) and statically linked binaries. There is no glibc `dlopen` to probe.
- A glibc mapped since the last scan, for up to 5 minutes.
- Code mapped without `dlopen` at all (see reflective loading).
- Not verified: glibc's own module loads (NSS, iconv) use glibc-internal entry points, which may bypass the uprobe on the exported `dlopen` symbol.

### ptrace

`ptrace_monitor` hooks `sys_enter_ptrace`. It reports these requests, with the target PID, the target's comm (resolved in the caller's PID namespace) and, for POKE requests, the address:

| Request class | Requests | Reported | Tested |
|---|---|---|---|
| Attach | `PTRACE_ATTACH` | Yes | Yes |
| Attach | `PTRACE_SEIZE` | Yes | No |
| Attach | `PTRACE_TRACEME` (the target asks to be traced) | No | — |
| Memory write | `PTRACE_POKETEXT`, `PTRACE_POKEDATA` | Yes | No |
| USER-area write | `PTRACE_POKEUSER` | Yes | Yes |
| Register write | `PTRACE_SETREGS` (x86; not on arm64), `PTRACE_SETREGSET` | Yes | Yes |
| Other writes | `PTRACE_SETFPREGS`, `PTRACE_SETFPXREGS`, `PTRACE_SETSIGINFO`, `PTRACE_SET_THREAD_AREA`, arch-specific | No | — |
| Reads | `PEEK*`, `GETREGS`, `GETREGSET`, `GETSIGINFO` | No | — |
| Control | `CONT`, `SYSCALL`, `SINGLESTEP`, `DETACH`, `INTERRUPT`, `LISTEN`, `KILL` | No | — |

After `PTRACE_TRACEME`, the tracer's writes are still reported; `TestSensor6_PtraceMonitor_RegisterWrites` traces a child that way. The target comm is empty when the target is in a PID namespace nested below the caller's. The kernel's Yama `ptrace_scope` setting limits who can trace whom; HookMon does not check it.

### process_vm_writev and /proc/<pid>/mem

Both write directly into another process's memory without ptrace. Neither is covered. They were placed out of scope in the fix plan.

### memfd and reflective loading

A binary can run without a file on disk: write it to a `memfd_create` file and exec it through the descriptor. `exec_injection` still reports any `LD_*` variable, because it fires on every exec. Nothing flags the fileless exec itself, and `elf_rpath` cannot read `/dev/fd/N` once the process is gone.

A library in a memfd loaded with `dlopen("/proc/self/fd/N")` goes through `dlopen`, so `dlopen_monitor` reports it with that path (code reading).

Reflective loaders map an ELF image themselves, without `dlopen`. Shellcode and JIT engines write code into executable memory (`mmap` or `mprotect` with `PROT_EXEC`). None of this is covered. It was placed out of scope in the fix plan.

### Shared memory

Shared memory is not code by itself. HookMon watches it because bpftime uses it to talk to its injected runtime.

`shm_monitor` hooks `sys_enter_openat` and `sys_enter_openat2` and reports opens with `O_CREAT` of a path that starts with `/dev/shm/`, which is what glibc's `shm_open` does. Severity follows the name: CRITICAL for bpftime's names, ALERT for other names containing `bpf` as a word. Any other segment is not reported, only counted.

Not covered:
- Relative or dirfd-relative opens, `/run/shm`, `creat()`, `O_TMPFILE` followed by `linkat`, and renames into `/dev/shm`.
- Opens submitted through io_uring, which do not pass through the syscall tracepoints.
- System V shared memory (`shmget`), memfd, and shared mappings of ordinary files.

### Kernel modules and binfmt_misc

A kernel module runs with full kernel privilege. It can hide processes, files and BPF programs, and it can disable HookMon. Module loading (`init_module`, `finit_module`) is not monitored. Neither is livepatch.

`binfmt_misc` lets root register an interpreter for executables that match a pattern. Every matching exec then runs that interpreter first. Registrations are not monitored.

### Static binaries and musl

A static binary has no dynamic linker. `LD_*` variables, linker configuration and RPATH do nothing to it, and it cannot load a library unless it carries its own loader. `exec_injection` still reports `LD_*` variables set on it.

For musl (Alpine and other musl-based images):
- `exec_injection`: covered. It reads the environment whatever the libc, and musl honors `LD_PRELOAD` and `LD_LIBRARY_PATH`.
- `elf_rpath`: covered. The analysis reads the ELF file, whatever the libc.
- `dlopen_monitor`: not covered. Only glibc is probed.
- `linker_config`: not applicable. musl reads `/etc/ld-musl-<arch>.path`, which is not watched, and ignores `ld.so.preload` and `ld.so.cache`.
- `lib_integrity`: musl libraries under the watched directories on the host are covered. Those inside container images are not.

## What HookMon Trusts

**Root on the monitored host.** Root can defeat HookMon. It can:
- kill the bus and serve a fake "alive" `/status`;
- write fresh timestamps into a heartbeat map after detaching a hook;
- load a kernel module;
- replace the bus binary, its config, or the `hookmon-dlopen-probe` helper the bus runs every 10 seconds.

Killing the bus outright is detected (the host goes unreachable), and so is a detached hook whose heartbeat is not forged. A clean stop (SIGTERM/SIGINT) is announced to the server, which suppresses the AGENT_OFFLINE alert; SIGKILL or an OOM kill is not announced, so the watchdog fires. The bus also sends an end-to-end marker every 60 seconds through the gRPC stream, so the server can detect a wedged bus-to-server path even when heartbeats succeed. The rest is not detected. [SECURITY.md](../SECURITY.md) has the details.

**The kernel.** Every sensor depends on tracepoints, uprobes, fanotify and BTF reporting honestly. A kernel rootkit defeats all of them.

**Package-manager ancestry.** A file change by a process whose ancestry includes a package manager is not reported, only counted as suppressed. A malicious package's install scripts, or an attacker who makes the change through a package manager, is not reported.

**Directory ownership.** `dlopen_monitor` and `LD_LIBRARY_PATH` trust a library, or a search path, that only root can change. Root planting a library outside the directories `lib_integrity` watches, then loading it with `dlopen`, is not reported.

**`/proc` at enrichment time.** Process context is read from `/proc` after the event arrives. A process that has exited gets less context; a file-sensor writer that has exited gets UID 4294967295 ("unknown"). If a PID is reused in between, the context could in principle belong to the wrong process.

**The bus's self-filter.** The bus drops every event whose PID or parent PID is its own. Only its own `bpf()` calls and its probe processes should match. Anything else that runs as a child of the bus is invisible.

**Deduplication.** `dlopen_monitor` reports each (binary, library) pair at most once an hour, and `elf_rpath` reports each binary version once. Repeated use inside those windows is not reported.

**The network.** Loki pushes and `/status` are unauthenticated plain HTTP. gRPC to the server requires mutual TLS (the server refuses to start without a certificate unless `--insecure`). The collector's SSH mode verifies host keys against `ssh_known_hosts` (fail closed).

**Time between checks.** The collector polls every 30 seconds and the bus checks hooks every 10. An attack that completes and cleans up inside that window, while the bus is down, is missed. Persistent changes are not: BPF programs still loaded show in the next inventory. Files changed while the bus was down are not reported, because the next startup takes their new hashes as the baseline.
