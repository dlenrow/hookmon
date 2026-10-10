/*
 * execveat_canary.c — runs a binary through execveat(2) with LD_PRELOAD set.
 *
 * Opens the target and replaces itself with it through
 * execveat(fd, "", ..., AT_EMPTY_PATH), the call fexecve(3) makes: no path
 * reaches execve(), and the kernel names the new program /dev/fd/<fd>. The
 * environment holds only LD_PRELOAD. The exec_injection sensor must report
 * it like any other exec.
 *
 * Usage: ./execveat_canary <path-to-so> <target-binary>
 *   e.g. ./execveat_canary /tmp/canary/bin/libfake_hook.so /bin/true
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <path-to-so> <target-binary>\n", argv[0]);
        return 1;
    }

    size_t len = strlen("LD_PRELOAD=") + strlen(argv[1]) + 1;
    char *preload = malloc(len);
    if (!preload) {
        perror("malloc");
        return 1;
    }
    snprintf(preload, len, "LD_PRELOAD=%s", argv[1]);

    int fd = open(argv[2], O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    char *const new_argv[] = {argv[2], NULL};
    char *const new_envp[] = {preload, NULL};
    syscall(SYS_execveat, fd, "", new_argv, new_envp, AT_EMPTY_PATH);
    perror("execveat");
    return 1;
}
