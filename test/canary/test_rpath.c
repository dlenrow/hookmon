/*
 * test_rpath.c — Canary binary for testing ELF RPATH detection.
 *
 * Compile with a suspicious RPATH baked in:
 *   gcc -o test_rpath test_rpath.c -Wl,-rpath,/tmp/evil
 *
 * Or with $ORIGIN (less suspicious in non-SUID context):
 *   gcc -o test_rpath_origin test_rpath.c '-Wl,-rpath,$ORIGIN/../lib'
 *
 * Or with a RUNPATH $ORIGIN entry that resolves to a writable directory
 * (HIGH if world-writable, CRITICAL under /tmp, /home, ...):
 *   gcc -o test_rpath_origin_tmp test_rpath.c '-Wl,--enable-new-dtags,-rpath,$ORIGIN/../tmp'
 *
 * Verify with readelf:
 *   readelf -d test_rpath | grep -i path
 *
 * When run under hookmon-agent, executing this binary should produce
 * an ELF_RPATH event with CRITICAL risk due to /tmp/evil.
 */
#include <stdio.h>

int main(void) {
    printf("test_rpath canary: hello from a binary with suspicious RPATH\n");
    return 0;
}
