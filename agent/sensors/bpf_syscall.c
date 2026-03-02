// SPDX-License-Identifier: Apache-2.0
// eBPF program: monitor bpf() syscall invocations
//
// Attaches to tracepoint/syscalls/sys_enter_bpf and captures
// BPF_PROG_LOAD, BPF_PROG_ATTACH, and BPF_MAP_CREATE commands.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define BPF_PROG_NAME_LEN 16

#define BPF_MAP_CREATE    0
#define BPF_PROG_LOAD     5
#define BPF_PROG_ATTACH   8

#define EVENT_BPF_LOAD 1

struct hook_event {
    u32 event_type;
    u32 pid;
    u32 uid;
    u32 gid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    u32 bpf_cmd;
    u32 prog_type;
    char prog_name[BPF_PROG_NAME_LEN];
    u32 attach_type;
    u32 insn_count;
    u64 insns_ptr;   // userspace pointer to BPF instructions (for hash computation)
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf_enter(struct trace_event_raw_sys_enter *ctx)
{
    u32 cmd = (u32)ctx->args[0];

    // Only capture program load, attach, and map create
    if (cmd != BPF_PROG_LOAD && cmd != BPF_PROG_ATTACH && cmd != BPF_MAP_CREATE)
        return 0;

    struct hook_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = EVENT_BPF_LOAD;
    e->bpf_cmd = cmd;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read bpf_attr for program details (only for PROG_LOAD)
    if (cmd == BPF_PROG_LOAD) {
        union bpf_attr *attr = (union bpf_attr *)ctx->args[1];
        bpf_probe_read_user(&e->prog_type, sizeof(e->prog_type), &attr->prog_type);
        bpf_probe_read_user_str(e->prog_name, sizeof(e->prog_name), (void *)attr->prog_name);
        bpf_probe_read_user(&e->insn_count, sizeof(e->insn_count), &attr->insn_cnt);

        // Capture the userspace pointer to BPF instructions for hash computation
        u64 insns;
        bpf_probe_read_user(&insns, sizeof(insns), &attr->insns);
        e->insns_ptr = insns;
    }

    if (cmd == BPF_PROG_ATTACH) {
        union bpf_attr *attr = (union bpf_attr *)ctx->args[1];
        bpf_probe_read_user(&e->attach_type, sizeof(e->attach_type), &attr->attach_type);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
