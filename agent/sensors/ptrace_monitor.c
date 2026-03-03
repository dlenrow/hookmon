// SPDX-License-Identifier: Apache-2.0
// eBPF program: monitor ptrace() for dangerous requests
//
// Attaches to tracepoint/syscalls/sys_enter_ptrace and filters for
// PTRACE_ATTACH, PTRACE_SEIZE, PTRACE_POKETEXT, PTRACE_POKEDATA.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define EVENT_PTRACE_INJECT 8

// ptrace request constants
#define PTRACE_ATTACH    16
#define PTRACE_SEIZE     0x4206
#define PTRACE_POKETEXT  4
#define PTRACE_POKEDATA  5

struct ptrace_event {
    u32 event_type;
    u32 pid;
    u32 uid;
    u32 gid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    u32 ptrace_request;
    u32 target_pid;
    u64 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace_enter(struct trace_event_raw_sys_enter *ctx)
{
    u32 request = (u32)ctx->args[0];

    // Filter: only care about dangerous requests
    if (request != PTRACE_ATTACH &&
        request != PTRACE_SEIZE &&
        request != PTRACE_POKETEXT &&
        request != PTRACE_POKEDATA)
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

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
