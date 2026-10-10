// SPDX-License-Identifier: Apache-2.0
// eBPF program: monitor creation of /dev/shm segments
//
// Attaches to tracepoint/syscalls/sys_enter_openat and sys_enter_openat2 and
// filters for filenames under /dev/shm/ opened with O_CREAT, to detect
// userspace eBPF runtimes that communicate via shared memory segments.
// glibc's shm_open() is an openat() on /dev/shm/<name>.
//
// Each event also carries the first SHM_ENV_LEN bytes of the creating
// process's environment. bpftime renames its segment through an environment
// variable, and Go matches it against the segment name. The copy is taken
// here, while the creator is still running; Go reads /proc/<pid>/environ only
// when the environment is longer than the copy.
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
#define SHM_ENV_LEN 4096

#define EVENT_SHM_CREATE 4

// O_CREAT is 0100 (octal) on x86 and arm64.
#define HOOKMON_O_CREAT 0x40

// /dev/shm/ prefix is 9 bytes
#define DEV_SHM_PREFIX_LEN 9

// Mirrored by shmEvent in shm_monitor.go, which reads it with binary.Read.
// Every field is naturally aligned, so there is no padding.
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
    u32 env_len;    // bytes of env copied; 0 if the read failed
    u32 env_total;  // size of the creator's whole environment
    char env[SHM_ENV_LEN];
};

_Static_assert(sizeof(struct hook_event) == 4276, "hook_event layout changed; update shm_monitor.go");

// Each record is about 4 KiB, so the buffer holds about 240 of them.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

// Heartbeat maps — written at most every HOOKMON_HEARTBEAT_INTERVAL_NS (1 s)
// whenever the hook fires, one per hook. The bus fires both hooks itself every
// 10 s and checks that the older value moved, so the throttle must stay well
// under 10 s.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hookmon_heartbeat_shm_monitor SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hookmon_heartbeat_shm_monitor_openat2 SEC(".maps");

#define HOOKMON_HEARTBEAT_INTERVAL_NS (1ULL * 1000000000ULL)

static __always_inline void hookmon_heartbeat(void *map) {
    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(map, &key);
    if (!last || (now - *last) >= HOOKMON_HEARTBEAT_INTERVAL_NS) {
        bpf_map_update_elem(map, &key, &now, BPF_ANY);
    }
}

// read_shm_path copies filename into path and returns 1 if it names a
// segment under /dev/shm/.
static __always_inline int read_shm_path(const char *filename, char *path)
{
    if (!filename)
        return 0;

    int ret = bpf_probe_read_user_str(path, SHM_NAME_LEN, filename);
    if (ret <= DEV_SHM_PREFIX_LEN)
        return 0;

    // Check for "/dev/shm/" prefix
    if (path[0] != '/' || path[1] != 'd' || path[2] != 'e' || path[3] != 'v' ||
        path[4] != '/' || path[5] != 's' || path[6] != 'h' || path[7] != 'm' ||
        path[8] != '/')
        return 0;
    return 1;
}

static __always_inline int emit_shm_event(const char *path, u32 flags, u32 mode)
{
    // Only care about creation
    if (!(flags & HOOKMON_O_CREAT))
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
    e->mode = mode;

    // The creator's environment: the strings the kernel placed at exec,
    // the same bytes /proc/<pid>/environ shows.
    e->env_len = 0;
    e->env_total = 0;
    u64 env_start = BPF_CORE_READ(task, mm, env_start);
    u64 env_end = BPF_CORE_READ(task, mm, env_end);
    if (env_end > env_start) {
        u64 total = env_end - env_start;
        e->env_total = total > 0xffffffffULL ? 0xffffffffU : (u32)total;
        u32 n = total > SHM_ENV_LEN ? SHM_ENV_LEN : (u32)total;
        if (n > 0 && n <= SHM_ENV_LEN &&
            bpf_probe_read_user(e->env, n, (const void *)env_start) == 0)
            e->env_len = n;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_shm_open(struct trace_event_raw_sys_enter *ctx)
{
    hookmon_heartbeat(&hookmon_heartbeat_shm_monitor);
    // sys_enter_openat args: [0]=dfd, [1]=filename, [2]=flags, [3]=mode
    char path[SHM_NAME_LEN];
    if (!read_shm_path((const char *)ctx->args[1], path))
        return 0;
    return emit_shm_event(path, (u32)ctx->args[2], (u32)ctx->args[3]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_shm_openat2(struct trace_event_raw_sys_enter *ctx)
{
    hookmon_heartbeat(&hookmon_heartbeat_shm_monitor_openat2);
    // sys_enter_openat2 args: [0]=dfd, [1]=filename, [2]=struct open_how *,
    // [3]=size. open_how starts with u64 flags, then u64 mode.
    char path[SHM_NAME_LEN];
    if (!read_shm_path((const char *)ctx->args[1], path))
        return 0;
    u64 how[2] = {};
    if (bpf_probe_read_user(how, sizeof(how), (const void *)ctx->args[2]) != 0)
        return 0;
    return emit_shm_event(path, (u32)how[0], (u32)how[1]);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
