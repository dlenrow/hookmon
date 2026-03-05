/*
 * ptrace_canary.c — Canary for testing ptrace injection sensor detection.
 *
 * Forks a child, then uses ptrace(PTRACE_ATTACH) to attach to it.
 * This should trigger the ptrace_monitor eBPF sensor.
 *
 * Usage: ./ptrace_canary
 *
 * Build: cc -o ptrace_canary ptrace_canary.c
 */

#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        /* Child: sleep to give parent time to attach */
        printf("[ptrace_canary] child pid=%d, sleeping...\n", getpid());
        sleep(5);
        printf("[ptrace_canary] child exiting\n");
        _exit(0);
    }

    /* Parent: attach to child via ptrace */
    usleep(200000); /* let child start */

    printf("[ptrace_canary] parent attaching to child pid=%d\n", child);

    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) < 0) {
        perror("ptrace(PTRACE_ATTACH)");
        kill(child, 9);
        waitpid(child, NULL, 0);
        return 1;
    }

    /* Wait for child to stop */
    int status;
    waitpid(child, &status, 0);
    printf("[ptrace_canary] child stopped (status=0x%x)\n", status);

    /* Brief pause to let sensor process */
    usleep(500000);

    /* Detach and let child continue */
    ptrace(PTRACE_DETACH, child, NULL, NULL);
    printf("[ptrace_canary] detached from child\n");

    /* Wait for child to finish */
    waitpid(child, &status, 0);
    printf("[ptrace_canary] child exited\n");

    return 0;
}
