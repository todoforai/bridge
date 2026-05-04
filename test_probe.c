// Smoke test for bridge_pty_probe_blocked.
// Spawns a shell, runs `read -r v`, sleeps to let it block on stdin, probes.
// Then runs sudo (if present) to test the password_prompt flag.
#define _POSIX_C_SOURCE 200809L
#include "pty.h"
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static void msleep(int ms) { struct timespec ts={ms/1000,(ms%1000)*1000000L}; nanosleep(&ts,NULL); }

static void drain(bridge_pty_t *p, int total_ms) {
    int fd = bridge_pty_pollfd(p);
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int waited = 0;
    while (waited < total_ms) {
        struct pollfd pf = { .fd = fd, .events = POLLIN };
        int pr = poll(&pf, 1, 50);
        waited += 50;
        if (pr > 0 && (pf.revents & POLLIN)) {
            char buf[4096];
            ssize_t n;
            while ((n = read(fd, buf, sizeof(buf))) > 0) { (void)n; }
        }
    }
    fcntl(fd, F_SETFL, flags);
}

int main(void) {
    // 1) plain `read` — should detect blocked, ECHO on => not password
    {
        bridge_pty_t p;
        if (bridge_pty_spawn(&p, "/bin/sh", NULL, /*no_echo=*/1) != 0) { fprintf(stderr, "spawn failed\n"); return 1; }
        const char *cmd = "read -r v; echo got=$v\n";
        bridge_pty_write_all(&p, cmd, strlen(cmd));
        drain(&p, 300);
        pid_t fg=0; int pwd=0;
        int r = bridge_pty_probe_blocked(&p, /*echo_baseline=*/0, &fg, &pwd);
        printf("[read]  blocked=%d fg=%d pwd=%d\n", r, (int)fg, pwd); fflush(stdout);
        bridge_pty_write_all(&p, "hi\n", 3);
        msleep(100);
        bridge_pty_close(&p);
    }
    // 2) `read -s` — ECHO off, password prompt true. Spawn with no_echo=0 so
    // baseline=1 and the echo-off transition is detected.
    {
        bridge_pty_t p;
        if (bridge_pty_spawn(&p, "/bin/bash", NULL, /*no_echo=*/0) != 0) { fprintf(stderr, "spawn failed\n"); return 1; }
        const char *cmd = "read -s -p 'pw: ' v; echo got=$v\n";
        bridge_pty_write_all(&p, cmd, strlen(cmd));
        drain(&p, 400);
        pid_t fg=0; int pwd=0;
        int r = bridge_pty_probe_blocked(&p, /*echo_baseline=*/1, &fg, &pwd);
        printf("[read -s] blocked=%d fg=%d pwd=%d (expect pwd=1)\n", r, (int)fg, pwd); fflush(stdout);
        bridge_pty_write_all(&p, "hi\n", 3);
        msleep(100);
        bridge_pty_close(&p);
    }
    // 3) busy command — should NOT be blocked
    {
        bridge_pty_t p;
        if (bridge_pty_spawn(&p, "/bin/sh", NULL, /*no_echo=*/1) != 0) { fprintf(stderr, "spawn failed\n"); return 1; }
        const char *cmd = "while :; do :; done\n";
        bridge_pty_write_all(&p, cmd, strlen(cmd));
        drain(&p, 300);
        pid_t fg=0; int pwd=0;
        int r = bridge_pty_probe_blocked(&p, /*echo_baseline=*/1, &fg, &pwd);
        printf("[busy]  blocked=%d fg=%d pwd=%d (expect blocked=0)\n", r, (int)fg, pwd); fflush(stdout);
        bridge_pty_signal(&p, 9);
        bridge_pty_close(&p);
    }
    return 0;
}
