// SPDX-License-Identifier: Apache-2.0
// eBPF program: report dangerous linker environment variables on every exec
//
// Attaches to tracepoint/sched/sched_process_exec, which fires once the new
// image is installed, for execve and execveat alike, before the new program
// runs. By then the kernel has copied the environment onto the new stack,
// between mm->env_start and mm->env_end, so the program reads exactly the
// strings ld.so will read. A hook on sys_enter_execve reads the caller's
// copy instead: another thread can rewrite it before the kernel copies it,
// and a page that is not resident cannot be read from BPF at all. Neither
// applies here: the new process has one thread and has not run, and the
// kernel has just written these pages.
//
// The environment is a run of NUL-terminated strings. The program reads it
// ENV_READ_LEN bytes at a time, so a variable shorter than that takes one
// read, and checks the start of each variable for LD_PRELOAD=, LD_AUDIT=,
// LD_LIBRARY_PATH= and LD_DEBUG=. If the reads run out before env_end, a
// read fails, or more than MAX_MATCHES variables match, the scan stops and
// one more event goes out flagged EXEC_INJ_SCAN_TRUNCATED. A variable past
// the limit is never missed silently.
//
// Two programs share the scan. exec_injection_loop runs it through
// bpf_loop (kernel 5.17 and later), which the verifier checks once,
// whatever the count. exec_injection_bounded is a plain loop the verifier
// walks iteration by iteration, for older kernels; its limit is far lower.
// The Go side loads one of them.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256
#define ENV_VAR_LEN 32

// Bytes per read of the environment. A variable shorter than this takes one
// read; a longer one takes one per ENV_READ_LEN - 1 bytes.
#define ENV_READ_LEN 256

// Reads per exec, mirrored in exec_injection.go. bpf_loop accepts up to
// 1 << 23, more than any environment the kernel allows, so the limit is set
// by run time instead: the program runs with preemption off, and a read
// costs 50-95 ns on an i3-8109U, so 8192 reads take under 1 ms. The bounded
// loop is limited by the verifier: on 5.19 it accepts 768 iterations and
// rejects 896 ("The sequence of 8193 jumps is too complex"). At 512 it
// processes about half of the 1M instructions allowed, leaving room for
// older verifiers.
#ifndef MAX_ENV_READS
#define MAX_ENV_READS 8192
#endif
#ifndef MAX_ENV_READS_BOUNDED
#define MAX_ENV_READS_BOUNDED 512
#endif

// Matching variables reported per exec. More than this stops the scan, so
// one exec cannot flood the ring buffer.
#define MAX_MATCHES 16

#define EVENT_EXEC_INJECTION 3

#define EXEC_INJ_SCAN_TRUNCATED  (1U << 0)
#define EXEC_INJ_VALUE_TRUNCATED (1U << 1)
// The process's root directory is its parent's, so Go can resolve the
// library path under the parent's root after the process has exited.
#define EXEC_INJ_PARENT_ROOT     (1U << 2)

#define VAR_LD_PRELOAD      1
#define VAR_LD_AUDIT        2
#define VAR_LD_LIBRARY_PATH 3
#define VAR_LD_DEBUG        4

struct hook_event {
    u32 event_type;
    u32 pid;
    u32 uid;
    u32 gid;
    u32 ppid;
    u32 flags;      // EXEC_INJ_*
    u32 mnt_ns;     // mount namespace inode, to resolve the library path
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];    // bprm->filename, as passed to exec
    char env_value[MAX_PATH_LEN];   // the value after '='
    char env_var_name[ENV_VAR_LEN]; // empty on a truncation event
};

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
} hookmon_heartbeat_exec_injection SEC(".maps");

#define HOOKMON_HEARTBEAT_INTERVAL_NS (1ULL * 1000000000ULL)

static __always_inline void hookmon_heartbeat(void *map) {
    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(map, &key);
    if (!last || (now - *last) >= HOOKMON_HEARTBEAT_INTERVAL_NS) {
        bpf_map_update_elem(map, &key, &now, BPF_ANY);
    }
}

// W8 packs eight characters into the u64 an 8-byte little-endian load of
// them gives.
#define W8(a, b, c, d, e, f, g, h)                                            \
    ((u64)(a) | (u64)(b) << 8 | (u64)(c) << 16 | (u64)(d) << 24 |            \
     (u64)(e) << 32 | (u64)(f) << 40 | (u64)(g) << 48 | (u64)(h) << 56)

// Nothing the scan branches on may be a constant the verifier knows, for
// two reasons:
//  - Before kernel 6.7 the verifier checks a bpf_loop callback as if it ran
//    once, from the context it was given. A check against a value that is
//    constant there, such as a match count starting at 0, is taken to
//    always go one way and is removed as dead code.
//  - The bounded loop stays within the verifier's limits only while each
//    iteration's state can be pruned against an earlier one, and states
//    holding different constants cannot be.
// So the scan keeps var_start, read separately from ptr so the verifier
// does not know they are equal, rather than an "inside a variable" flag,
// and counts matches in match_count, a map, whose values the verifier never
// knows.
struct scan_ctx {
    u64 ptr;        // next byte of the environment to read
    u64 var_start;  // start of the variable ptr is in
    u64 end;        // mm->env_end
    u64 filename;   // kernel address of the tracepoint's filename
    u32 mnt_ns;
    u32 flags;      // EXEC_INJ_PARENT_ROOT, sent on every event
};

// Matches reported so far for the exec being scanned. A tracepoint program
// runs to completion on one CPU with preemption off and does not nest, so
// one slot per CPU is enough.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} match_count SEC(".maps");

// emit_event sends one event for the exec c is scanning. var is VAR_* for a
// matching variable whose value starts at user address value, or 0 for a
// truncation event.
//
// It is a global function, so the verifier checks it once rather than at
// every call site. A global function takes only scalars and pointers to
// sized memory, hence c rather than the tracepoint context.
__noinline int emit_event(struct scan_ctx *c, int var, u64 value, u32 flags)
{
    if (!c)
        return 0;   // the verifier requires the check for a global function

    struct hook_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = EVENT_EXEC_INJECTION;
    e->flags = c->flags | flags;
    e->mnt_ns = c->mnt_ns;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = uid_gid >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), (void *)c->filename);

    __builtin_memset(e->env_var_name, 0, sizeof(e->env_var_name));
    e->env_value[0] = '\0';
    if (var) {
        // A value that fills the buffer may have been cut short.
        long n = bpf_probe_read_user_str(e->env_value, sizeof(e->env_value), (void *)value);
        if (n < 0 || n == sizeof(e->env_value))
            e->flags |= EXEC_INJ_VALUE_TRUNCATED;
    }
    switch (var) {
    case VAR_LD_PRELOAD:
        __builtin_memcpy(e->env_var_name, "LD_PRELOAD", 10);
        break;
    case VAR_LD_AUDIT:
        __builtin_memcpy(e->env_var_name, "LD_AUDIT", 8);
        break;
    case VAR_LD_LIBRARY_PATH:
        __builtin_memcpy(e->env_var_name, "LD_LIBRARY_PATH", 15);
        break;
    case VAR_LD_DEBUG:
        __builtin_memcpy(e->env_var_name, "LD_DEBUG", 8);
        break;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// match_var returns the VAR_* whose "NAME=" starts s, or 0, and sets *len
// to the length of "NAME=". Bytes after the string's NUL are stale, but a
// match needs every byte up to the '=' to be part of the string.
static __always_inline int match_var(const char *s, int *len)
{
    u64 w0, w1;
    __builtin_memcpy(&w0, s, 8);
    __builtin_memcpy(&w1, s + 8, 8);

    if (w0 == W8('L', 'D', '_', 'P', 'R', 'E', 'L', 'O') &&
        s[8] == 'A' && s[9] == 'D' && s[10] == '=') {
        *len = 11;
        return VAR_LD_PRELOAD;
    }
    if (w0 == W8('L', 'D', '_', 'A', 'U', 'D', 'I', 'T') && s[8] == '=') {
        *len = 9;
        return VAR_LD_AUDIT;
    }
    if (w0 == W8('L', 'D', '_', 'L', 'I', 'B', 'R', 'A') &&
        w1 == W8('R', 'Y', '_', 'P', 'A', 'T', 'H', '=')) {
        *len = 16;
        return VAR_LD_LIBRARY_PATH;
    }
    if (w0 == W8('L', 'D', '_', 'D', 'E', 'B', 'U', 'G') && s[8] == '=') {
        *len = 9;
        return VAR_LD_DEBUG;
    }
    return 0;
}

// scan_step does one read of the environment. It returns 1 when the scan is
// over: the end was reached, or it stopped early, a read failing or a match
// past MAX_MATCHES. An early stop leaves ptr short of end, which is what
// scan_finish checks.
static __always_inline long scan_step(struct scan_ctx *c)
{
    char buf[ENV_READ_LEN] __attribute__((aligned(8)));

    if (c->ptr >= c->end)
        return 1;

    long n = bpf_probe_read_user_str(buf, sizeof(buf), (void *)c->ptr);
    if (n < 0)
        return 1;
    // An empty string: an empty variable, or the NUL that ends a variable
    // of exactly ENV_READ_LEN - 1 bytes. Kernel 5.19 returns 0 for it, not
    // the documented 1.
    if (n == 0)
        n = 1;

    if (c->ptr == c->var_start) {
        int len = 0;
        int var = match_var(buf, &len);
        if (var) {
            u32 key = 0;
            u32 *count = bpf_map_lookup_elem(&match_count, &key);
            if (!count || *count >= MAX_MATCHES)
                return 1;
            *count += 1;
            emit_event(c, var, c->ptr + len, 0);
        }
    }

    // n counts the NUL. A full buffer means the variable may go on: the
    // next read continues it at the byte that took the NUL's place.
    if (n == sizeof(buf)) {
        c->ptr += sizeof(buf) - 1;
    } else {
        c->ptr += n;
        c->var_start = c->ptr;
    }
    return 0;
}

static long scan_cb(u32 index, void *ctx)
{
    return scan_step(ctx);
}

// same_root_as_parent reports whether task's root directory is its
// parent's: the same mount and dentry.
static __always_inline int same_root_as_parent(struct task_struct *task)
{
    struct fs_struct *fs = BPF_CORE_READ(task, fs);
    struct fs_struct *pfs = BPF_CORE_READ(task, real_parent, fs);

    if (!fs || !pfs)
        return 0;
    return BPF_CORE_READ(fs, root.mnt) == BPF_CORE_READ(pfs, root.mnt) &&
           BPF_CORE_READ(fs, root.dentry) == BPF_CORE_READ(pfs, root.dentry);
}

static __always_inline void scan_init(struct scan_ctx *c,
                                      struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 key = 0;
    u32 *count = bpf_map_lookup_elem(&match_count, &key);

    if (count)
        *count = 0;
    c->ptr = BPF_CORE_READ(task, mm, env_start);
    c->var_start = BPF_CORE_READ(task, mm, env_start);
    c->end = BPF_CORE_READ(task, mm, env_end);
    c->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    if (same_root_as_parent(task))
        c->flags = EXEC_INJ_PARENT_ROOT;
    // filename is a __data_loc string: the low 16 bits are its offset from
    // the start of the tracepoint record.
    c->filename = (u64)(void *)ctx + (ctx->__data_loc_filename & 0xFFFF);
}

static __always_inline void scan_finish(struct scan_ctx *c)
{
    if (c->ptr < c->end)
        emit_event(c, 0, 0, EXEC_INJ_SCAN_TRUNCATED);
}

SEC("tracepoint/sched/sched_process_exec")
int exec_injection_loop(struct trace_event_raw_sched_process_exec *ctx)
{
    hookmon_heartbeat(&hookmon_heartbeat_exec_injection);

    struct scan_ctx c = {};
    scan_init(&c, ctx);
    bpf_loop(MAX_ENV_READS, scan_cb, &c, 0);
    scan_finish(&c);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int exec_injection_bounded(struct trace_event_raw_sched_process_exec *ctx)
{
    hookmon_heartbeat(&hookmon_heartbeat_exec_injection);

    struct scan_ctx c = {};
    scan_init(&c, ctx);
    for (int i = 0; i < MAX_ENV_READS_BOUNDED; i++) {
        if (scan_step(&c))
            break;
    }
    scan_finish(&c);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
