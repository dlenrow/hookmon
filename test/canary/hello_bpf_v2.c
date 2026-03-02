// SPDX-License-Identifier: Apache-2.0
// Canary eBPF program #3: hello_bpf_v2
// Revised version of hello_bpf with an additional per-UID counter.
// This is "App 1 v2" — same purpose but different bytecode, so a different hash.
// Tests that updating a program requires a new whitelist entry.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} hello_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u64);
} per_uid_counter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_getpid")
int hello_count_v2(struct trace_event_raw_sys_enter *ctx)
{
    u32 key = 0;
    u64 *count = bpf_map_lookup_elem(&hello_counter, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    // v2: also count per UID
    u32 uid = (u32)bpf_get_current_uid_gid();
    u64 *uid_count = bpf_map_lookup_elem(&per_uid_counter, &uid);
    if (uid_count) {
        __sync_fetch_and_add(uid_count, 1);
    } else {
        u64 init_val = 1;
        bpf_map_update_elem(&per_uid_counter, &uid, &init_val, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Apache-2.0";
