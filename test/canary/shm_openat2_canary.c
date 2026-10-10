/*
 * shm_openat2_canary.c — Canary for shm_monitor's openat2() hook.
 *
 * Creates a /dev/shm segment with openat2() instead of shm_open(), which
 * glibc implements with openat(). A sensor that hooks only openat() misses
 * this segment.
 *
 * Usage: ./shm_openat2_canary <segment-name>
 *   Creates /dev/shm/<segment-name>, holds it briefly, and removes it.
 *
 * Build: cc -o shm_openat2_canary shm_openat2_canary.c
 */

#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

int main(int argc, char *argv[]) {
    if (argc < 2 || strchr(argv[1], '/') != NULL) {
        fprintf(stderr, "usage: %s <segment-name without '/'>\n", argv[0]);
        return 2;
    }

    char path[256];
    snprintf(path, sizeof(path), "/dev/shm/%s", argv[1]);

    struct open_how how;
    memset(&how, 0, sizeof(how));
    how.flags = O_CREAT | O_RDWR | O_CLOEXEC;
    how.mode = 0600;

    printf("[shm_openat2_canary] openat2(%s, O_CREAT|O_RDWR)\n", path);
    int fd = (int)syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
    if (fd < 0) {
        perror("openat2");
        return 1;
    }
    if (ftruncate(fd, 4096) < 0)
        perror("ftruncate");

    /* Brief pause to let sensor process */
    usleep(500000);

    close(fd);
    unlink(path);
    printf("[shm_openat2_canary] cleaned up %s\n", path);
    return 0;
}
