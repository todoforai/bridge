// Smoke test: spawn a PTY with echo OFF, send a sentinel-wrapped command,
// confirm the output stream contains exactly the command output followed by
// the sentinel result line — i.e. no echoed wrapper text.
//
// Build: cc -O0 -g -Wall -o build/test-run test_run.c pty_posix.c -lutil
// Run:   ./build/test-run

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pty.h"

static int run_case(const char *label, const char *cmd, const char *expect_out, int expect_rc) {
    bridge_pty_t p;
    if (bridge_pty_spawn(&p, "/bin/sh", NULL, /*no_echo=*/1) != 0) {
        fprintf(stderr, "[%s] spawn failed\n", label);
        return 1;
    }

    const char *sentinel = "__BRIDGE_STEP_TEST_DEADBEEF__";
    char wrapped[4096];
    int wn = snprintf(wrapped, sizeof(wrapped),
        "{ %s\n}; __RC=$?; printf '\\n%s:%%d\\n' \"$__RC\"\n",
        cmd, sentinel);
    if (wn <= 0 || (size_t)wn >= sizeof(wrapped)) { fprintf(stderr, "[%s] wrapper too big\n", label); return 1; }

    if (bridge_pty_write_all(&p, wrapped, (size_t)wn) != 0) {
        fprintf(stderr, "[%s] write failed\n", label);
        bridge_pty_close(&p);
        return 1;
    }

    char buf[8192]; size_t total = 0;
    int rc = 1;
    for (int tries = 0; tries < 50 && total < sizeof(buf) - 1; tries++) {
        struct pollfd pfd = { .fd = bridge_pty_pollfd(&p), .events = POLLIN };
        int pr = poll(&pfd, 1, 500);
        if (pr <= 0) break;
        long n = bridge_pty_read(&p, buf + total, sizeof(buf) - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
        buf[total] = '\0';
        if (strstr(buf, sentinel) && strchr(strstr(buf, sentinel), '\n')) { rc = 0; break; }
    }

    if (rc != 0) {
        fprintf(stderr, "[%s] sentinel not seen. Got %zu bytes: %.*s\n", label, total, (int)total, buf);
        bridge_pty_close(&p);
        return 1;
    }

    // The pre-sentinel bytes (minus the leading '\n'/'\r\n' our printf injects)
    // must equal expect_out. Confirms PTY echo is actually off.
    char *sp = strstr(buf, sentinel);
    size_t pre = (size_t)(sp - buf);
    if (pre >= 2 && buf[pre - 2] == '\r' && buf[pre - 1] == '\n') pre -= 2;
    else if (pre >= 1 && buf[pre - 1] == '\n') pre -= 1;
    if (expect_out) {
        size_t elen = strlen(expect_out);
        if (pre != elen || memcmp(buf, expect_out, elen) != 0) {
            fprintf(stderr, "[%s] FAIL: pre-sentinel mismatch (exp %zub got %zub).\n",
                    label, elen, pre);
            fprintf(stderr, "  expected: ");
            for (size_t i = 0; i < elen; i++) {
                unsigned char c = (unsigned char)expect_out[i];
                if (c >= 32 && c < 127) fputc(c, stderr); else fprintf(stderr, "\\x%02x", c);
            }
            fprintf(stderr, "\n  got     : ");
            for (size_t i = 0; i < pre; i++) {
                unsigned char c = (unsigned char)buf[i];
                if (c >= 32 && c < 127) fputc(c, stderr); else fprintf(stderr, "\\x%02x", c);
            }
            fprintf(stderr, "\n");
            bridge_pty_close(&p);
            return 1;
        }
    }
    // Parse exit code from "<sentinel>:<int>\n".
    int got_rc = -999;
    char *colon = sp + strlen(sentinel);
    if (*colon == ':') sscanf(colon + 1, "%d", &got_rc);
    if (got_rc != expect_rc) {
        fprintf(stderr, "[%s] FAIL: rc=%d expected %d\n", label, got_rc, expect_rc);
        bridge_pty_close(&p);
        return 1;
    }

    fprintf(stderr, "[%s] OK (out=%zub, rc=%d)\n", label, pre, got_rc);
    bridge_pty_close(&p);
    return 0;
}

int main(void) {
    int fails = 0;
    fails += run_case("simple",     "echo hello",                        "hello\r\n",         0);
    fails += run_case("dquote",     "echo \"hi there\"",                 "hi there\r\n",      0);
    fails += run_case("squote",     "echo 'a b c'",                      "a b c\r\n",         0);
    fails += run_case("nonzero",    "false",                             "",                  1);
    fails += run_case("multi",      "echo a; echo b",                    "a\r\nb\r\n",        0);
    // Sentinel collision: user output happens to look like another sentinel.
    // With per-step random sentinels in production this is astronomically
    // unlikely; this test just confirms our scanner correctly finishes on the
    // FIRST match (so a real sentinel collision would prematurely terminate —
    // documented limitation, mitigated by random generation).
    fails += run_case("non-colliding-payload", "printf '__BRIDGE_STEP_OTHER__:0\\n'",
                                               "__BRIDGE_STEP_OTHER__:0\r\n", 0);
    if (fails) fprintf(stderr, "\n%d test(s) failed\n", fails);
    else       fprintf(stderr, "\nall tests passed\n");
    return fails ? 1 : 0;
}
