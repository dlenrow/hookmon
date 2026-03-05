/*
 * shm_canary.c — Canary for testing shared memory sensor detection.
 *
 * Creates a /dev/shm segment with a bpftime naming pattern, triggering
 * the shm_monitor eBPF sensor independently of the full bpftime simulator.
 *
 * Usage: ./shm_canary [shm-name]
 *   Default shm-name: /bpftime_canary_test
 *
 * Build: cc -o shm_canary shm_canary.c -lrt
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define DEFAULT_SHM_NAME "/bpftime_canary_test"
#define SHM_SIZE 4096

int main(int argc, char *argv[]) {
    const char *shm_name = (argc > 1) ? argv[1] : DEFAULT_SHM_NAME;

    printf("[shm_canary] creating shared memory: %s\n", shm_name);

    int fd = shm_open(shm_name, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        perror("shm_open");
        return 1;
    }

    if (ftruncate(fd, SHM_SIZE) < 0) {
        perror("ftruncate");
        close(fd);
        shm_unlink(shm_name);
        return 1;
    }

    void *addr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        shm_unlink(shm_name);
        return 1;
    }

    memcpy(addr, "shm_canary_marker", 17);
    printf("[shm_canary] created shm %s (fd=%d)\n", shm_name, fd);

    /* Brief pause to let sensor process */
    usleep(500000);

    /* Cleanup */
    munmap(addr, SHM_SIZE);
    close(fd);
    shm_unlink(shm_name);
    printf("[shm_canary] cleaned up %s\n", shm_name);

    return 0;
}
