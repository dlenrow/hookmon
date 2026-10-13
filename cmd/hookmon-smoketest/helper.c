// SPDX-License-Identifier: Apache-2.0
// HookMon smoketest helper: a dynamically-linked binary with two jobs.
//
// 1. When exec'd, its DT_RUNPATH (/tmp/hookmon-smoketest) triggers the
//    elf_rpath sensor (CRITICAL: under /tmp).
// 2. With "dlopen <path>", it calls dlopen on the library, triggering the
//    dlopen_monitor uprobe.
//
// Build:
//   cc -O2 -o hookmon-smoketest-helper helper.c -ldl \
//      -Wl,--enable-new-dtags,-rpath,/tmp/hookmon-smoketest

//go:build ignore

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc >= 3 && strcmp(argv[1], "dlopen") == 0) {
        void *h = dlopen(argv[2], RTLD_NOW);
        if (!h) {
            fprintf(stderr, "dlopen: %s\n", dlerror());
            return 1;
        }
        dlclose(h);
        return 0;
    }
    return 0;
}
