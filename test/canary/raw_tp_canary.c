// SPDX-License-Identifier: Apache-2.0
// Canary eBPF program: raw_tp_canary
// A raw tracepoint program on sys_enter. Attaching it goes through
// BPF_RAW_TRACEPOINT_OPEN, which the bpf_syscall sensor reports as BPF_ATTACH.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} raw_tp_counter SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int raw_tp_count(struct bpf_raw_tracepoint_args *ctx)
{
    u32 key = 0;
    u64 *count = bpf_map_lookup_elem(&raw_tp_counter, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    return 0;
}

char LICENSE[] SEC("license") = "Apache-2.0";
