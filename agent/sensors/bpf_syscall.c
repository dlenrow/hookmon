// SPDX-License-Identifier: Apache-2.0
// eBPF program: monitor bpf() syscall invocations
//
// Captures BPF_PROG_LOAD and the attach commands BPF_PROG_ATTACH,
// BPF_LINK_CREATE and BPF_RAW_TRACEPOINT_OPEN. BPF_MAP_CREATE is not
// captured: a map runs no code, and any program that uses one is reported by
// its own PROG_LOAD.
//
// sys_enter_bpf records the call's arguments per thread; sys_exit_bpf emits
// the event. For PROG_LOAD the exit is where the kernel's view exists: the
// return value is the new program's fd, so the exit handler reads that
// program's ID and tag straight from the kernel before the loader can close
// it. For the attach commands, the enter handler resolves the program fd the
// caller passed.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define BPF_PROG_NAME_LEN 16
#define BPF_TAG_LEN 8
#define ATTACH_TARGET_LEN 64

#define BPF_PROG_LOAD           5
#define BPF_PROG_ATTACH         8
#define BPF_RAW_TRACEPOINT_OPEN 17
#define BPF_LINK_CREATE         28

#define EVENT_BPF_LOAD 1

// Mirrored by bpfSyscallEvent in bpf_syscall.go, which reads it with
// binary.Read. Every field is naturally aligned, so there is no padding.
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
    s32 target_fd;
    u32 prog_id;                 // 0: load failed, or fd did not resolve
    u8  tag[BPF_TAG_LEN];        // kernel's bpf_prog->tag
    char attach_target[ATTACH_TARGET_LEN];
};

_Static_assert(sizeof(struct hook_event) == 148, "hook_event layout changed; update bpf_syscall.go");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Calls seen at sys_enter_bpf and not yet returned, keyed by pid_tgid. A
// thread is in at most one syscall, so enter and exit pair up exactly. LRU
// so an entry whose exit was never seen cannot fill the map.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct hook_event);
} pending SEC(".maps");

// Heartbeat map — written at most every HOOKMON_HEARTBEAT_INTERVAL_NS (1 s)
// whenever the hook fires. The bus fires every hook itself every 10 s and
// checks that this value moved, so the throttle must stay well under 10 s.
// Key 0 = last heartbeat timestamp (bpf_ktime_get_ns()).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hookmon_heartbeat_bpf_syscall SEC(".maps");

// Same, written by the exit handler. Events are emitted at exit, so the bus
// treats the sensor as alive only if both values move.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hookmon_heartbeat_bpf_syscall_exit SEC(".maps");

#define HOOKMON_HEARTBEAT_INTERVAL_NS (1ULL * 1000000000ULL)

static __always_inline void hookmon_heartbeat(void *map) {
    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(map, &key);
    if (!last || (now - *last) >= HOOKMON_HEARTBEAT_INTERVAL_NS) {
        bpf_map_update_elem(map, &key, &now, BPF_ANY);
    }
}

// prog_from_fd looks up fd in the current task's fd table and, if it refers
// to a BPF program, records the program's ID and tag. A BPF program file's
// private_data is the struct bpf_prog, and prog->aux->prog points back at
// it; that check rejects fds that are not BPF programs.
static __always_inline void prog_from_fd(s32 fd, struct hook_event *e)
{
    if (fd < 0)
        return;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
    if (!fdt)
        return;
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if ((u32)fd >= max_fds)
        return;

    struct file **fds = BPF_CORE_READ(fdt, fd);
    struct file *f = NULL;
    if (bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]) || !f)
        return;

    struct bpf_prog *prog = BPF_CORE_READ(f, private_data);
    if (!prog)
        return;
    struct bpf_prog_aux *aux = BPF_CORE_READ(prog, aux);
    if (!aux || BPF_CORE_READ(aux, prog) != prog)
        return;

    e->prog_id = BPF_CORE_READ(aux, id);
    BPF_CORE_READ_INTO(&e->tag, prog, tag);
}

// A syscalls:sys_enter_*/sys_exit_* tracepoint's record is struct
// syscall_trace_enter/_exit, not struct trace_event_raw_sys_enter/_exit (the
// raw_syscalls record). Upstream both put args and ret at byte 16, but RHEL 9
// grows the common header, which moves the raw_syscalls fields to 24: CO-RE
// on the wrong struct reads 8 bytes off, and the kernel refuses the attach
// when the last read runs past the record.
SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf_enter(struct syscall_trace_enter *ctx)
{
    hookmon_heartbeat(&hookmon_heartbeat_bpf_syscall);
    u32 cmd = (u32)ctx->args[0];

    if (cmd != BPF_PROG_LOAD && cmd != BPF_PROG_ATTACH &&
        cmd != BPF_LINK_CREATE && cmd != BPF_RAW_TRACEPOINT_OPEN)
        return 0;

    struct hook_event e = {};
    e.event_type = EVENT_BPF_LOAD;
    e.bpf_cmd = cmd;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e.pid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();
    e.uid = (u32)uid_gid;
    e.gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e.ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    union bpf_attr *attr = (union bpf_attr *)ctx->args[1];
    s32 prog_fd = -1;

    switch (cmd) {
    case BPF_PROG_LOAD:
        bpf_probe_read_user(&e.prog_type, sizeof(e.prog_type), &attr->prog_type);
        bpf_probe_read_user_str(e.prog_name, sizeof(e.prog_name), (void *)attr->prog_name);
        bpf_probe_read_user(&e.insn_count, sizeof(e.insn_count), &attr->insn_cnt);
        break;
    case BPF_PROG_ATTACH:
        bpf_probe_read_user(&e.attach_type, sizeof(e.attach_type), &attr->attach_type);
        bpf_probe_read_user(&e.target_fd, sizeof(e.target_fd), &attr->target_fd);
        bpf_probe_read_user(&prog_fd, sizeof(prog_fd), &attr->attach_bpf_fd);
        break;
    case BPF_LINK_CREATE:
        bpf_probe_read_user(&e.attach_type, sizeof(e.attach_type), &attr->link_create.attach_type);
        bpf_probe_read_user(&e.target_fd, sizeof(e.target_fd), &attr->link_create.target_fd);
        bpf_probe_read_user(&prog_fd, sizeof(prog_fd), &attr->link_create.prog_fd);
        break;
    case BPF_RAW_TRACEPOINT_OPEN: {
        u64 name = 0;
        bpf_probe_read_user(&name, sizeof(name), &attr->raw_tracepoint.name);
        if (name)
            bpf_probe_read_user_str(e.attach_target, sizeof(e.attach_target), (void *)name);
        bpf_probe_read_user(&prog_fd, sizeof(prog_fd), &attr->raw_tracepoint.prog_fd);
        break;
    }
    }

    // The attach commands name an existing program by fd; it is open now.
    if (cmd != BPF_PROG_LOAD)
        prog_from_fd(prog_fd, &e);

    bpf_map_update_elem(&pending, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_bpf")
int trace_bpf_exit(struct syscall_trace_exit *ctx)
{
    hookmon_heartbeat(&hookmon_heartbeat_bpf_syscall_exit);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct hook_event *p = bpf_map_lookup_elem(&pending, &pid_tgid);
    if (!p)
        return 0;

    struct hook_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        if (bpf_probe_read_kernel(e, sizeof(*e), p)) {
            bpf_ringbuf_discard(e, 0);
        } else {
            // A successful PROG_LOAD returns the new program's fd.
            long ret = ctx->ret;
            if (e->bpf_cmd == BPF_PROG_LOAD && ret >= 0)
                prog_from_fd((s32)ret, e);
            bpf_ringbuf_submit(e, 0);
        }
    }
    bpf_map_delete_elem(&pending, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
