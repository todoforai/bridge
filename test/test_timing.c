// Timing harness: measure the pure bridge-side cost of a one-shot RUN with
// zero network — spawn → write → first output byte → sentinel (done).
// Mirrors main.c's run path (echo off, sentinel-wrapped command).
//
// Build: cc -O0 -g -Wall -o build/test-timing test/test_timing.c pty_posix.c -lutil
// Run:   ./build/test-timing
//
// Columns (ms): spawn = forkpty+exec; warmup = spawn→first output byte
// (shell startup before the command emits anything); run = firstByte→sentinel;
// total = spawn+warmup+run.

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "pty.h"

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void time_case(const char *label, const char *cmd) {
    double t0 = now_ms();
    bridge_pty_t p;
    if (bridge_pty_spawn(&p, "/bin/sh", NULL, /*no_echo=*/1) != 0) {
        fprintf(stderr, "[%s] spawn failed\n", label);
        return;
    }
    double t_spawned = now_ms();

    const char *sentinel = "__BRIDGE_TIMING_SENTINEL__";
    char wrapped[4096];
    int wn = snprintf(wrapped, sizeof(wrapped),
        "{ %s\n}; __RC=$?; printf '\\n%s:%%d\\n' \"$__RC\"\n", cmd, sentinel);
    if (wn <= 0 || (size_t)wn >= sizeof(wrapped)) { bridge_pty_close(&p); return; }
    bridge_pty_write_all(&p, wrapped, (size_t)wn);

    static char buf[1u << 20]; size_t total = 0;
    double t_first = -1;
    for (int tries = 0; tries < 2000 && total < sizeof(buf) - 1; tries++) {
        struct pollfd pfd = { .fd = bridge_pty_pollfd(&p), .events = POLLIN };
        if (poll(&pfd, 1, 1000) <= 0) break;
        long n = bridge_pty_read(&p, buf + total, sizeof(buf) - 1 - total);
        if (n <= 0) break;
        if (t_first < 0) t_first = now_ms();
        total += (size_t)n;
        buf[total] = '\0';
        if (strstr(buf, sentinel)) break;
    }
    double t_done = now_ms();
    bridge_pty_close(&p);

    double spawn  = t_spawned - t0;
    double warmup = (t_first >= 0 ? t_first - t_spawned : -1);
    double run    = (t_first >= 0 ? t_done - t_first : -1);
    printf("%-14s spawn=%6.1f  warmup=%6.1f  run=%6.1f  total=%6.1f  (out=%zub)\n",
           label, spawn, warmup, run, t_done - t0, total);
}

int main(void) {
    printf("=== bridge one-shot RUN timing (ms, no network) ===\n");
    // Warm the page cache / loader once so the first real row isn't skewed.
    time_case("(warmup)",   "true");
    time_case("true",       "true");
    time_case("echo",       "echo hello");
    time_case("pwd",        "pwd");
    time_case("ls",         "ls -la /usr/bin >/dev/null");
    time_case("sleep0.2",   "sleep 0.2");
    time_case("100lines",   "for i in $(seq 1 100); do echo line $i; done");
    // Large multi-chunk output (~500 KiB): exercises draining across many
    // BUF_SIZE reads in one go (the drain loop the daemon uses per tick).
    time_case("bigoutput",  "yes ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 | head -16000");
    time_case("which-many", "for t in sh ls cat grep awk sed; do command -v $t; done >/dev/null");
    return 0;
}
