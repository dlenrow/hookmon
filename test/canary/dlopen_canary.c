/*
 * dlopen_canary.c — Canary for testing dlopen() sensor detection.
 *
 * Loads a shared library via dlopen() at runtime, which should trigger
 * the dlopen_monitor eBPF uprobe sensor.
 *
 * Usage: ./dlopen_canary <path-to-so>
 *   e.g. ./dlopen_canary /tmp/libfake_hook.so
 *
 * Build: cc -o dlopen_canary dlopen_canary.c -ldl
 */

#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path-to-so>\n", argv[0]);
        return 1;
    }

    const char *lib_path = argv[1];
    printf("[dlopen_canary] loading %s via dlopen(RTLD_NOW)\n", lib_path);

    void *handle = dlopen(lib_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "[dlopen_canary] dlopen failed: %s\n", dlerror());
        return 1;
    }

    printf("[dlopen_canary] successfully loaded %s\n", lib_path);

    /* Brief pause to let sensor process the event */
    usleep(500000);

    dlclose(handle);
    printf("[dlopen_canary] closed library\n");

    return 0;
}
