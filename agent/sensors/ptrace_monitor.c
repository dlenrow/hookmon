// SPDX-License-Identifier: Apache-2.0
// eBPF program: monitor ptrace() for dangerous requests
//
// Attaches to tracepoint/syscalls/sys_enter_ptrace and filters for the
// requests that attach to a process or write its memory or registers:
// PTRACE_ATTACH, PTRACE_SEIZE, PTRACE_POKETEXT, PTRACE_POKEDATA,
// PTRACE_POKEUSER, PTRACE_SETREGS and PTRACE_SETREGSET.
//
// The target is a PID in the caller's PID namespace, which BPF on this
// kernel cannot look up. The event carries the caller's PID namespace, and
// Go resolves the target's comm in that namespace.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define EVENT_PTRACE_INJECT 8

// ptrace request constants (include/uapi/linux/ptrace.h;
// PTRACE_SETREGS is 13 on x86 and arm, and absent on arm64)
#define PTRACE_POKETEXT   4
#define PTRACE_POKEDATA   5
#define PTRACE_POKEUSER   6
#define PTRACE_SETREGS    13
#define PTRACE_ATTACH     16
#define PTRACE_SETREGSET  0x4205
#define PTRACE_SEIZE      0x4206

// Mirrored by ptraceMonitorEvent in ptrace_monitor.go, which reads it with
// binary.Read. binary.Read does not pad, so every field must be naturally
// aligned: addr sits at offset 48.
struct ptrace_event {
    u32 event_type;
    u32 pid;
    u32 uid;
    u32 gid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    u32 ptrace_request;
    u32 target_pid;
    u32 pidns_inum;   // inode number of the caller's PID namespace
    u64 addr;
};

_Static_assert(sizeof(struct ptrace_event) == 56, "ptrace_event layout changed; update ptrace_monitor.go");
_Static_assert(__builtin_offsetof(struct ptrace_event, addr) == 48, "addr must not follow padding");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Heartbeat map — written at most every HOOKMON_HEARTBEAT_INTERVAL_NS (1 s)
// whenever the hook fires. The bus fires every hook itself every 10 s and
// checks that this value moved, so the throttle must stay well under 10 s.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hookmon_heartbeat_ptrace_monitor SEC(".maps");

#define HOOKMON_HEARTBEAT_INTERVAL_NS (1ULL * 1000000000ULL)

static __always_inline void hookmon_heartbeat(void *map) {
    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(map, &key);
    if (!last || (now - *last) >= HOOKMON_HEARTBEAT_INTERVAL_NS) {
        bpf_map_update_elem(map, &key, &now, BPF_ANY);
    }
}

// pidns_inum returns the inode number of task's active PID namespace, the
// namespace its ptrace() target PID is resolved in (the kernel's
// task_active_pid_ns()).
static __always_inline u32 pidns_inum(struct task_struct *task)
{
    struct pid *pid = BPF_CORE_READ(task, thread_pid);
    if (!pid)
        return 0;
    unsigned int level = BPF_CORE_READ(pid, level);
    struct upid upid = {};
    if (bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]) != 0 || !upid.ns)
        return 0;
    return BPF_CORE_READ(upid.ns, ns.inum);
}

// The context is struct syscall_trace_enter, this tracepoint's own record;
// bpf_syscall.c says why not struct trace_event_raw_sys_enter.
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace_enter(struct syscall_trace_enter *ctx)
{
    hookmon_heartbeat(&hookmon_heartbeat_ptrace_monitor);
    u32 request = (u32)ctx->args[0];

    // Filter: only care about dangerous requests
    if (request != PTRACE_ATTACH &&
        request != PTRACE_SEIZE &&
        request != PTRACE_POKETEXT &&
        request != PTRACE_POKEDATA &&
        request != PTRACE_POKEUSER &&
        request != PTRACE_SETREGS &&
        request != PTRACE_SETREGSET)
        return 0;

    struct ptrace_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = EVENT_PTRACE_INJECT;
    e->ptrace_request = request;
    e->target_pid = (u32)ctx->args[1];
    e->addr = (u64)ctx->args[2];

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->pidns_inum = pidns_inum(task);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
