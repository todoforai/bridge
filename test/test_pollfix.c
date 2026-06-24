// Demonstrates the 50ms-floor bug and its fix in-process, deterministically.
//
// OLD loop: the PTY master fd is NOT in the pollset (only a quiet "WS" pipe is),
// so poll() blocks the full 50ms timeout before service reads ready PTY output.
// NEW loop: the PTY master fd IS in the pollset, so poll() returns the instant
// output is available.
//
// Build: cc -O0 -g -Wall -I. -o build/test-pollfix test/test_pollfix.c pty_posix.c env_path.c -lutil
// Run:   ./build/test-pollfix

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pty.h"

static double now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

// quiet_fd stands in for the WS socket: a pipe read end with nothing to read,
// so poll() on it only ever returns via timeout (mirrors an idle connection).
static double measure(const char *label, int pty_in_pollset) {
    int q[2]; (void)!pipe(q);
    bridge_pty_t p;
    bridge_pty_spawn(&p, "/bin/sh", NULL, 1);
    const char *sentinel = "__POLLFIX__";
    char w[256];
    int wn = snprintf(w, sizeof w, "{ echo hi\n}; printf '\\n%s:%%d\\n' $?\n", sentinel);
    double t0 = now_ms();
    bridge_pty_write_all(&p, w, (size_t)wn);

    char buf[4096]; size_t total = 0; double t_first = -1;
    for (int i = 0; i < 200; i++) {
        struct pollfd pfds[2];
        pfds[0].fd = q[0]; pfds[0].events = POLLIN;  // "WS" — always quiet
        nfds_t n = 1;
        if (pty_in_pollset) { pfds[1].fd = bridge_pty_pollfd(&p); pfds[1].events = POLLIN; n = 2; }
        poll(pfds, n, 50);                            // same 50ms ceiling as the daemon
        long r = bridge_pty_read(&p, buf + total, sizeof buf - 1 - total);
        if (r > 0) { if (t_first < 0) t_first = now_ms(); total += (size_t)r; buf[total] = 0;
                     if (strstr(buf, sentinel)) break; }
    }
    double dt = (t_first >= 0 ? t_first - t0 : -1);
    bridge_pty_close(&p); close(q[0]); close(q[1]);
    printf("%-28s firstByte=%6.2f ms\n", label, dt);
    return dt;
}

int main(void) {
    printf("=== poll-fix demonstration (50ms ceiling, idle WS) ===\n");
    measure("OLD (PTY not in pollset)", 0);
    measure("NEW (PTY in pollset)", 1);
    return 0;
}
