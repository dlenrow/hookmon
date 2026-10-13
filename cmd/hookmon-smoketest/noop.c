// SPDX-License-Identifier: Apache-2.0
// No-op shared library for HookMon smoketest.
// Used as the LD_PRELOAD and dlopen target. The constructor is harmless;
// its presence is what HookMon detects.
//
// Build: cc -shared -fPIC -o libhookmon_smoketest.so noop.c

//go:build ignore

#include <stddef.h>

__attribute__((constructor))
static void hookmon_smoketest_init(void) {
    // intentionally empty
}
