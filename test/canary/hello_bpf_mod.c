// SPDX-License-Identifier: Apache-2.0
// Canary eBPF program: hello_bpf_mod
// hello_bpf.c with one instruction changed: it adds 2 instead of 1. Same
// program name, same map, same section. Its kernel tag must differ from
// hello_bpf's, which shows the tag covers the instructions themselves.

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
        __sync_fetch_and_add(count, 2);
    return 0;
}

char LICENSE[] SEC("license") = "Apache-2.0";
