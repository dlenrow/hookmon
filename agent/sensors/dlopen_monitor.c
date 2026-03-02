// SPDX-License-Identifier: Apache-2.0
// eBPF program: monitor dlopen() calls for runtime library injection
//
// Attaches as uprobe on libc/libdl dlopen to detect processes loading
// shared libraries at runtime (potential code injection vector).

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256

#define EVENT_DLOPEN 5

struct hook_event {
    u32 event_type;
    u32 pid;
    u32 uid;
    u32 gid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char library_path[MAX_PATH_LEN];
    int flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("uprobe/dlopen")
int trace_dlopen(struct pt_regs *ctx)
{
    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    if (!filename)
        return 0;

    struct hook_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = EVENT_DLOPEN;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->library_path, sizeof(e->library_path), filename);

    e->flags = (int)PT_REGS_PARM2(ctx);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Apache-2.0";
