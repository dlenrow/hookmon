// SPDX-License-Identifier: Apache-2.0
// hookmon-dlopen-probe: fires the dlopen_monitor uprobe for the sensor bus.
//
// The bus is a static Go binary and cannot call libc's dlopen itself, so
// every heartbeat cycle it runs this helper. dlopen(NULL) enters the exported
// dlopen symbol the uprobe is attached to and returns a handle to the main
// program without loading anything. The uprobe writes its heartbeat before
// it checks the filename, and a NULL filename is not reported as an event.
//
// Build: $(CC) -O2 -o hookmon-dlopen-probe dlopen_probe.c -ldl
// Modelled on test/canary/dlopen_canary.c.

//go:build ignore

#include <dlfcn.h>
#include <stddef.h>

int main(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle)
        return 1;
    dlclose(handle);
    return 0;
}
