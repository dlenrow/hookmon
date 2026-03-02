// SPDX-License-Identifier: Apache-2.0
// eBPF program: monitor execve() for LD_PRELOAD environment variable
//
// Attaches to tracepoint/syscalls/sys_enter_execve and scans the
// environment pointer array for LD_PRELOAD entries.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256
#define MAX_ENV_VARS 64
#define LD_PRELOAD_PREFIX "LD_PRELOAD="
#define LD_PRELOAD_PREFIX_LEN 11

#define EVENT_LD_PRELOAD 3

struct hook_event {
    u32 event_type;
    u32 pid;
    u32 uid;
    u32 gid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
    char preload_value[MAX_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    // args[0] = filename, args[1] = argv, args[2] = envp
    const char *const *envp = (const char *const *)ctx->args[2];
    const char *filename = (const char *)ctx->args[0];

    if (!envp)
        return 0;

    char env_entry[MAX_PATH_LEN];

    // Scan first MAX_ENV_VARS environment variables
    #pragma unroll
    for (int i = 0; i < MAX_ENV_VARS; i++) {
        const char *env_ptr = NULL;
        bpf_probe_read_user(&env_ptr, sizeof(env_ptr), &envp[i]);
        if (!env_ptr)
            break;

        int ret = bpf_probe_read_user_str(env_entry, sizeof(env_entry), env_ptr);
        if (ret <= 0)
            continue;

        // Check for "LD_PRELOAD=" prefix
        if (env_entry[0] == 'L' && env_entry[1] == 'D' && env_entry[2] == '_' &&
            env_entry[3] == 'P' && env_entry[4] == 'R' && env_entry[5] == 'E' &&
            env_entry[6] == 'L' && env_entry[7] == 'O' && env_entry[8] == 'A' &&
            env_entry[9] == 'D' && env_entry[10] == '=') {

            struct hook_event *e;
            e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (!e)
                return 0;

            e->event_type = EVENT_LD_PRELOAD;

            u64 pid_tgid = bpf_get_current_pid_tgid();
            e->pid = pid_tgid >> 32;

            u64 uid_gid = bpf_get_current_uid_gid();
            e->uid = (u32)uid_gid;
            e->gid = uid_gid >> 32;

            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            e->ppid = BPF_CORE_READ(task, real_parent, tgid);

            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

            // Copy the LD_PRELOAD value (after the "=" sign)
            // The full env_entry is "LD_PRELOAD=/path/to/lib.so"
            // Copy starting from index 11
            __builtin_memcpy(e->preload_value, &env_entry[LD_PRELOAD_PREFIX_LEN],
                             sizeof(e->preload_value) - LD_PRELOAD_PREFIX_LEN);

            bpf_ringbuf_submit(e, 0);
            return 0;
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "Apache-2.0";
