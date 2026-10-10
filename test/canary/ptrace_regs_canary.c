/*
 * ptrace_regs_canary.c — Canary for ptrace register and USER-area writes.
 *
 * Forks a child that renames itself, asks to be traced (PTRACE_TRACEME) and
 * stops. The parent then writes the child's registers back unchanged with
 * PTRACE_SETREGS and PTRACE_SETREGSET, writes one word of its USER area back
 * unchanged with PTRACE_POKEUSER, and kills it. Each write should trigger
 * the ptrace_monitor eBPF sensor, with the child's name as the target comm.
 *
 * Usage: ./ptrace_regs_canary [target-comm]
 *   Default target-comm: hm_ptrace_tgt (at most 15 characters are kept).
 *   Prints "target_pid=<pid>" once the child has stopped, and on x86_64
 *   "pokeuser_addr=<offset>", the USER-area offset passed to PTRACE_POKEUSER.
 *
 * Build: cc -o ptrace_regs_canary ptrace_regs_canary.c
 */

#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    const char *target_comm = (argc > 1) ? argv[1] : "hm_ptrace_tgt";

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        prctl(PR_SET_NAME, target_comm, 0, 0, 0);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace(PTRACE_TRACEME)");
            _exit(1);
        }
        raise(SIGSTOP);
        _exit(0);
    }

    int status;
    if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status)) {
        fprintf(stderr, "[ptrace_regs_canary] child did not stop (status=0x%x)\n", status);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }
    printf("target_pid=%d\n", child);
    fflush(stdout);

    int failures = 0;

#if defined(__x86_64__) || defined(__i386__)
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0 ||
        ptrace(PTRACE_SETREGS, child, NULL, &regs) < 0) {
        perror("ptrace(PTRACE_SETREGS)");
        failures++;
    } else {
        printf("[ptrace_regs_canary] PTRACE_SETREGS ok\n");
    }
#endif

    struct user_regs_struct regset;
    struct iovec iov = { .iov_base = &regset, .iov_len = sizeof(regset) };
    if (ptrace(PTRACE_GETREGSET, child, (void *)NT_PRSTATUS, &iov) < 0 ||
        ptrace(PTRACE_SETREGSET, child, (void *)NT_PRSTATUS, &iov) < 0) {
        perror("ptrace(PTRACE_SETREGSET)");
        failures++;
    } else {
        printf("[ptrace_regs_canary] PTRACE_SETREGSET ok\n");
    }

#if defined(__x86_64__)
    long off = (long)offsetof(struct user, regs.r14);
    printf("pokeuser_addr=%ld\n", off);
    fflush(stdout);
    errno = 0;
    long word = ptrace(PTRACE_PEEKUSER, child, (void *)off, NULL);
    if (errno != 0 || ptrace(PTRACE_POKEUSER, child, (void *)off, (void *)word) < 0) {
        perror("ptrace(PTRACE_POKEUSER)");
        failures++;
    } else {
        printf("[ptrace_regs_canary] PTRACE_POKEUSER ok\n");
    }
#else
    /* Not every architecture has a USER area to write (arm64 rejects the
     * request), but the call still reaches sys_enter_ptrace. */
    ptrace(PTRACE_POKEUSER, child, NULL, NULL);
#endif

    /* Brief pause to let sensor process */
    usleep(500000);

    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    printf("[ptrace_regs_canary] done, %d failure(s)\n", failures);
    return failures ? 1 : 0;
}
