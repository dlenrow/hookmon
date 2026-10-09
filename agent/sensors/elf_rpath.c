// SPDX-License-Identifier: Apache-2.0
// eBPF program: report every successful exec for ELF RPATH/RUNPATH analysis
//
// Attaches to tracepoint/sched/sched_process_exec. The tracepoint fires once
// the new image is installed, for execve and execveat alike, so
// current->mm->exe_file is already the binary that was loaded. The program
// reports the filename as passed to exec plus the identity of that binary
// (device, inode, mtime, mode). Go keys its analysis cache on the identity,
// and before analysing a file it opens, it checks the file is the one the
// kernel loaded. No filtering happens here: Go analyses every exec.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256

struct exec_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u64 dev;        // exe_file->f_inode->i_sb->s_dev (kernel dev_t encoding)
    u64 ino;
    s64 mtime_sec;
    u32 mtime_nsec;
    u32 mode;       // i_mode: file type and permission bits, incl. setuid
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];  // bprm->filename, as passed to exec
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
} hookmon_heartbeat_elf_rpath SEC(".maps");

#define HOOKMON_HEARTBEAT_INTERVAL_NS (1ULL * 1000000000ULL)

static __always_inline void hookmon_heartbeat(void *map) {
    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(map, &key);
    if (!last || (now - *last) >= HOOKMON_HEARTBEAT_INTERVAL_NS) {
        bpf_map_update_elem(map, &key, &now, BPF_ANY);
    }
}

// struct inode's mtime has had three layouts. CO-RE picks the one the
// running kernel has; the other branches are dead code after relocation.
struct inode___pre67 {
    struct timespec64 i_mtime;          // up to 6.6
} __attribute__((preserve_access_index));

struct inode___v67 {
    struct timespec64 __i_mtime;        // 6.7 - 6.10
} __attribute__((preserve_access_index));

struct inode___v611 {
    time64_t i_mtime_sec;               // 6.11 and later
    u32 i_mtime_nsec;
} __attribute__((preserve_access_index));

static __always_inline void read_mtime(struct inode *inode, s64 *sec, u32 *nsec)
{
    struct inode___v611 *i611 = (void *)inode;
    struct inode___v67 *i67 = (void *)inode;
    struct inode___pre67 *ipre = (void *)inode;

    if (bpf_core_field_exists(i611->i_mtime_sec)) {
        *sec = BPF_CORE_READ(i611, i_mtime_sec);
        *nsec = BPF_CORE_READ(i611, i_mtime_nsec);
    } else if (bpf_core_field_exists(i67->__i_mtime)) {
        *sec = BPF_CORE_READ(i67, __i_mtime.tv_sec);
        *nsec = BPF_CORE_READ(i67, __i_mtime.tv_nsec);
    } else {
        *sec = BPF_CORE_READ(ipre, i_mtime.tv_sec);
        *nsec = BPF_CORE_READ(ipre, i_mtime.tv_nsec);
    }
}

SEC("tracepoint/sched/sched_process_exec")
int rpath_on_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    hookmon_heartbeat(&hookmon_heartbeat_elf_rpath);

    struct exec_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // filename is a __data_loc string: the low 16 bits are its offset from
    // the start of the tracepoint record.
    u32 loc = ctx->__data_loc_filename;
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
                              (void *)ctx + (loc & 0xFFFF));

    struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
    if (inode) {
        e->dev = BPF_CORE_READ(inode, i_sb, s_dev);
        e->ino = BPF_CORE_READ(inode, i_ino);
        e->mode = BPF_CORE_READ(inode, i_mode);
        read_mtime(inode, &e->mtime_sec, &e->mtime_nsec);
    } else {
        e->dev = 0;
        e->ino = 0;
        e->mode = 0;
        e->mtime_sec = 0;
        e->mtime_nsec = 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
