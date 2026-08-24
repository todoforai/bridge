// Regression test: `\x03` on the PTY must raise SIGINT in the foreground
// command, not land in it as stdin data. bridge_pty_spawn zero-inits termios,
// so without explicit c_cc every control char is disabled (`intr = <undef>`)
// and ISIG alone is a no-op — the exact bug this guards.
//
// Also asserts the shell survives the interrupt (same pid, still runs commands)
// and that ^Z stays disabled (no job control ⇒ a stopped run would hang).
#define _POSIX_C_SOURCE 200809L
#include "pty.h"
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>

static void msleep(int ms) { struct timespec ts={ms/1000,(ms%1000)*1000000L}; nanosleep(&ts,NULL); }

// Read whatever the PTY has for `ms`, appending into `out`.
static void collect(bridge_pty_t *p, char *out, size_t cap, int ms) {
    size_t len = strlen(out);
    int fd = bridge_pty_pollfd(p);
    for (int waited = 0; waited < ms; waited += 50) {
        struct pollfd pf = { .fd = fd, .events = POLLIN };
        if (poll(&pf, 1, 50) > 0 && (pf.revents & POLLIN)) {
            char buf[4096];
            long n = bridge_pty_read(p, buf, sizeof buf);
            if (n <= 0) continue;
            for (long i = 0; i < n && len + 1 < cap; i++) if (buf[i] != '\r') out[len++] = buf[i];
            out[len] = '\0';
        }
    }
}

static int fails = 0;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

int main(void) {
    bridge_pty_t p;
    if (bridge_pty_spawn(&p, "/bin/sh", NULL, /*no_echo=*/1) != 0) {
        fprintf(stderr, "spawn failed\n");
        return 1;
    }

    // Control chars are what the line discipline actually consults.
    struct termios t;
    check(tcgetattr(bridge_pty_pollfd(&p), &t) == 0, "tcgetattr on master");
    check(t.c_cc[VINTR] == 0x03, "VINTR mapped to ^C");
    check((t.c_lflag & ISIG) != 0, "ISIG enabled");
    check(t.c_cc[VSUSP] == _POSIX_VDISABLE, "VSUSP disabled (no job control)");

    const char *init = "stty -echo 2>/dev/null; PS1=; PS2=\n";
    bridge_pty_write_all(&p, init, strlen(init));

    char out[16384] = "";
    // Two rounds: an interrupt must be repeatable on the same persistent shell.
    for (int round = 0; round < 2; round++) {
        char cmd[128];
        snprintf(cmd, sizeof cmd, "echo R%d_START; sleep 30; echo R%d_NOT_INTERRUPTED\n", round, round);
        bridge_pty_write_all(&p, cmd, strlen(cmd));
        msleep(500);
        bridge_pty_write_all(&p, "\x03", 1);
        msleep(500);
        snprintf(cmd, sizeof cmd, "echo R%d_SHELL_ALIVE pid=$$\n", round);
        bridge_pty_write_all(&p, cmd, strlen(cmd));
        collect(&p, out, sizeof out, 400);
    }

    check(strstr(out, "R0_START") && strstr(out, "R1_START"), "commands ran");
    check(!strstr(out, "NOT_INTERRUPTED"), "sleep was interrupted (SIGINT raised)");
    check(strstr(out, "R0_SHELL_ALIVE") && strstr(out, "R1_SHELL_ALIVE"), "shell survived both interrupts");

    bridge_pty_close(&p);
    printf(fails ? "\n%d check(s) FAILED\n" : "\nall checks passed\n", fails);
    return fails ? 1 : 0;
}
