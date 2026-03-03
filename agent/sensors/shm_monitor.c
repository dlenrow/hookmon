// SPDX-License-Identifier: Apache-2.0
// eBPF program: monitor openat() calls targeting /dev/shm for bpftime-style patterns
//
// Attaches to tracepoint/syscalls/sys_enter_openat and filters for
// filenames under /dev/shm/ to detect userspace eBPF runtimes that
// communicate via shared memory segments.
//
// This approach is more reliable than a uprobe on shm_open because:
//   1. Tracepoint reads of user memory work on all kernel versions
//   2. It catches both shm_open() and direct open("/dev/shm/...") calls
//   3. No dependency on libc path or symbol versioning

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define SHM_NAME_LEN 128

#define EVENT_SHM_CREATE 4

// /dev/shm/ prefix is 9 bytes
#define DEV_SHM_PREFIX_LEN 9

struct hook_event {
    u32 event_type;
    u32 pid;
    u32 uid;
    u32 gid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char shm_name[SHM_NAME_LEN];
    u32 oflag;
    u32 mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_shm_open(struct trace_event_raw_sys_enter *ctx)
{
    // sys_enter_openat args: [0]=dfd, [1]=filename, [2]=flags, [3]=mode
    const char *filename = (const char *)ctx->args[1];
    if (!filename)
        return 0;

    // Read the filename into a stack buffer
    char path[SHM_NAME_LEN];
    int ret = bpf_probe_read_user_str(path, sizeof(path), filename);
    if (ret <= DEV_SHM_PREFIX_LEN)
        return 0;

    // Check for "/dev/shm/" prefix
    if (path[0] != '/' || path[1] != 'd' || path[2] != 'e' || path[3] != 'v' ||
        path[4] != '/' || path[5] != 's' || path[6] != 'h' || path[7] != 'm' ||
        path[8] != '/')
        return 0;

    // Only care about creation (O_CREAT = 0x40)
    u32 flags = (u32)ctx->args[2];
    if (!(flags & 0x40))
        return 0;

    struct hook_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = EVENT_SHM_CREATE;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Copy the segment name (strip /dev/shm/ prefix)
    __builtin_memcpy(e->shm_name, &path[DEV_SHM_PREFIX_LEN],
                     sizeof(e->shm_name) - DEV_SHM_PREFIX_LEN);

    e->oflag = flags;
    e->mode = (u32)ctx->args[3];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
