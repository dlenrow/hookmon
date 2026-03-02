/*
 * bpftime_sim.c — Simulates the observable footprint of a bpftime-go attack.
 *
 * This program reproduces the two signals that HookMon's sensors detect:
 *   1. shm_open("/bpftime_agent_shm") — triggers the shm_monitor uprobe
 *   2. execve() with LD_PRELOAD set    — triggers the execve_preload tracepoint
 *
 * Usage: ./bpftime_sim <path-to-so> <target-binary>
 *   e.g. ./bpftime_sim /tmp/libfake_hook.so /bin/true
 *
 * The program cleans up the shared memory segment before exiting and sleeps
 * briefly to give the agent time to process events.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define SHM_NAME "/bpftime_agent_shm"
#define SHM_SIZE 4096

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <path-to-so> <target-binary>\n", argv[0]);
        return 1;
    }

    const char *lib_path = argv[1];
    const char *target_bin = argv[2];

    /* Phase 1: Create shared memory segment with bpftime naming pattern.
     * This is how bpftime communicates between the agent and the hooked
     * target process — a shared memory region holds the eBPF VM state. */
    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        perror("shm_open");
        return 1;
    }

    if (ftruncate(fd, SHM_SIZE) < 0) {
        perror("ftruncate");
        close(fd);
        shm_unlink(SHM_NAME);
        return 1;
    }

    void *addr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        shm_unlink(SHM_NAME);
        return 1;
    }

    /* Write a marker so the segment isn't empty */
    memcpy(addr, "bpftime_sim_marker", 18);

    printf("[bpftime_sim] created shm %s (fd=%d, size=%d)\n", SHM_NAME, fd, SHM_SIZE);

    /* Brief pause to let the shm_monitor sensor process the event */
    usleep(500000);

    /* Phase 2: Fork and exec the target binary with LD_PRELOAD set.
     * This is how bpftime-go injects its runtime into the target process —
     * the preloaded library hooks function entry points via the PLT. */
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        munmap(addr, SHM_SIZE);
        close(fd);
        shm_unlink(SHM_NAME);
        return 1;
    }

    if (child == 0) {
        /* Child: exec target with LD_PRELOAD */
        setenv("LD_PRELOAD", lib_path, 1);
        printf("[bpftime_sim] child exec: LD_PRELOAD=%s %s\n", lib_path, target_bin);
        execl(target_bin, target_bin, NULL);
        perror("execl");
        _exit(1);
    }

    /* Parent: wait for child */
    int status;
    waitpid(child, &status, 0);
    printf("[bpftime_sim] child exited with status %d\n", WEXITSTATUS(status));

    /* Brief pause to let the execve_preload sensor process the event */
    usleep(500000);

    /* Cleanup */
    munmap(addr, SHM_SIZE);
    close(fd);
    shm_unlink(SHM_NAME);
    printf("[bpftime_sim] cleaned up shm %s\n", SHM_NAME);

    return 0;
}
