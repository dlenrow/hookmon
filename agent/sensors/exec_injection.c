// SPDX-License-Identifier: Apache-2.0
// eBPF program: monitor execve() for dangerous linker environment variables
//
// Attaches to tracepoint/syscalls/sys_enter_execve and scans the
// environment pointer array for LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH,
// and LD_DEBUG entries.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256
#define ENV_VAR_LEN 32
#define MAX_ENV_VARS 64

#define EVENT_EXEC_INJECTION 3

struct hook_event {
    u32 event_type;
    u32 pid;
    u32 uid;
    u32 gid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
    char env_value[MAX_PATH_LEN];
    char env_var_name[ENV_VAR_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// emit_event fills common fields and submits a ringbuf event.
static __always_inline void emit_event(const char *filename,
                                       const char *value, int value_len,
                                       const char *var_name, int var_name_len)
{
    struct hook_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->event_type = EVENT_EXEC_INJECTION;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    // Copy the value (everything after the '=')
    if (value_len > 0 && value_len < MAX_PATH_LEN)
        __builtin_memcpy(e->env_value, value, value_len);

    // Copy the variable name
    if (var_name_len > 0 && var_name_len < ENV_VAR_LEN)
        __builtin_memcpy(e->env_var_name, var_name, var_name_len);

    bpf_ringbuf_submit(e, 0);
}

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

        // Check for "LD_PRELOAD=" prefix (11 chars)
        if (env_entry[0] == 'L' && env_entry[1] == 'D' && env_entry[2] == '_' &&
            env_entry[3] == 'P' && env_entry[4] == 'R' && env_entry[5] == 'E' &&
            env_entry[6] == 'L' && env_entry[7] == 'O' && env_entry[8] == 'A' &&
            env_entry[9] == 'D' && env_entry[10] == '=') {
            emit_event(filename, &env_entry[11], sizeof(env_entry) - 11,
                       "LD_PRELOAD", 11);
        }

        // Check for "LD_AUDIT=" prefix (9 chars)
        if (env_entry[0] == 'L' && env_entry[1] == 'D' && env_entry[2] == '_' &&
            env_entry[3] == 'A' && env_entry[4] == 'U' && env_entry[5] == 'D' &&
            env_entry[6] == 'I' && env_entry[7] == 'T' && env_entry[8] == '=') {
            emit_event(filename, &env_entry[9], sizeof(env_entry) - 9,
                       "LD_AUDIT", 9);
        }

        // Check for "LD_LIBRARY_PATH=" prefix (16 chars)
        if (env_entry[0] == 'L' && env_entry[1] == 'D' && env_entry[2] == '_' &&
            env_entry[3] == 'L' && env_entry[4] == 'I' && env_entry[5] == 'B' &&
            env_entry[6] == 'R' && env_entry[7] == 'A' && env_entry[8] == 'R' &&
            env_entry[9] == 'Y' && env_entry[10] == '_' && env_entry[11] == 'P' &&
            env_entry[12] == 'A' && env_entry[13] == 'T' && env_entry[14] == 'H' &&
            env_entry[15] == '=') {
            emit_event(filename, &env_entry[16], sizeof(env_entry) - 16,
                       "LD_LIBRARY_PATH", 16);
        }

        // Check for "LD_DEBUG=" prefix (9 chars)
        if (env_entry[0] == 'L' && env_entry[1] == 'D' && env_entry[2] == '_' &&
            env_entry[3] == 'D' && env_entry[4] == 'E' && env_entry[5] == 'B' &&
            env_entry[6] == 'U' && env_entry[7] == 'G' && env_entry[8] == '=') {
            emit_event(filename, &env_entry[9], sizeof(env_entry) - 9,
                       "LD_DEBUG", 9);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
