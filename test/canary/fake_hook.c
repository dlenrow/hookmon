/*
 * fake_hook.c — Stub shared library for LD_PRELOAD testing.
 *
 * Simulates a malicious LD_PRELOAD hook. A real attack would interpose
 * functions like SSL_read, malloc, or open. This stub just logs that it
 * loaded, providing the LD_PRELOAD signal for HookMon's execve_preload
 * sensor to detect.
 *
 * Build: cc -shared -fPIC -o libfake_hook.so fake_hook.c
 */

#include <stdio.h>

__attribute__((constructor))
static void fake_hook_init(void) {
    fprintf(stderr, "[fake_hook] loaded via LD_PRELOAD\n");
}
