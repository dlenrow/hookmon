// SPDX-License-Identifier: Apache-2.0
// Canary eBPF program #2: net_monitor
// Attaches to sys_enter_connect tracepoint and counts connection attempts.
// This is "App 2" — a completely different BPF program with different bytecode hash.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} connect_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} last_pid SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int net_count(struct trace_event_raw_sys_enter *ctx)
{
    u32 key = 0;
    u64 *count = bpf_map_lookup_elem(&connect_counter, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *last = bpf_map_lookup_elem(&last_pid, &key);
    if (last)
        *last = pid;

    return 0;
}

char LICENSE[] SEC("license") = "Apache-2.0";
