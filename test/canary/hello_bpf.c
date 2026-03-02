// SPDX-License-Identifier: Apache-2.0
// Canary eBPF program #1: hello_bpf
// Attaches to sys_enter_getpid tracepoint and counts invocations.
// This is "App 1 v1" — used to test detection of a known BPF program.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} hello_counter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_getpid")
int hello_count(struct trace_event_raw_sys_enter *ctx)
{
    u32 key = 0;
    u64 *count = bpf_map_lookup_elem(&hello_counter, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    return 0;
}

char LICENSE[] SEC("license") = "Apache-2.0";
