// End-to-end on the real loop: drive RUN steps through service_sessions() the
// way a live bridge does, and record which frames come back. This is the
// regression that matters — a quiet-but-healthy command must reach step_done,
// while a genuine prompt must still park as step_awaiting_input.
//
// Pre-fix on macOS every command quiet for ~0.5s parked (XNU exposes no wait
// channel, so "asleep holding a pty fd" was read as proof of a tty read), and
// the backend answers a park on a tool install with Ctrl-C — which is how a
// healthy `npm install zele` died mid registry fetch.
//
// Includes main.c (Noise send shimmed, entry renamed). Build+run: make test-park
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define noise_ws_send bridge_test_noise_send
#define bridge_main bridge_main_unused
#include "../main.c"
#undef main

static int g_parked, g_done, g_pwd;
static char g_waiter[2048];

int bridge_test_noise_send(noise_ws_t *n, ws_t *w, const uint8_t *pt, size_t pt_len) {
    (void)n; (void)w;
    const char *json = (const char *)pt;
    const char *type = NULL; size_t type_len = 0;
    if (!json_get_str(json, pt_len, "type", &type, &type_len)) return 0;
    if (type_len == 19 && memcmp(type, "step_awaiting_input", 19) == 0) {
        g_parked++;
        int pwd = 0;
        if (json_get_bool(json, pt_len, "passwordPrompt", &pwd) && pwd) g_pwd++;
        const char *w = NULL; size_t wl = 0;
        g_waiter[0] = '\0';
        if (json_get_str(json, pt_len, "stdinWaiter", &w, &wl) && wl < sizeof g_waiter) {
            memcpy(g_waiter, w, wl); g_waiter[wl] = '\0';
        }
    } else if (type_len == 9 && memcmp(type, "step_done", 9) == 0) {
        g_done++;
    }
    return 0;
}

// Start a step on `s` exactly as the RUN handler does, then tick the loop until
// it settles (step_done or step_awaiting_input) or `budget_ms` runs out.
static void run_step(edge_t *e, session_t *s, const char *cmd, int no_input, int budget_ms) {
    g_parked = g_done = g_pwd = 0;

    ob_resolve(&s->ob, "raw", 3);
    snprintf(s->sentinel, sizeof s->sentinel, "__BRIDGE_STEP_PARK_TEST__");
    s->sentinel_len = strlen(s->sentinel);
    snprintf(s->run_block_id, sizeof s->run_block_id, "blk");
    s->run_block_id_len = 3;
    s->state = SESS_RUNNING;
    s->one_shot = 0;               // keep the PTY; later cases reuse the slot
    s->tail_len = 0;
    s->otail_len = 0;
    s->parked = 0;
    s->no_input = no_input;
    s->pause_consec_ticks = 0;
    s->last_active_ms = monotonic_ms();
    s->last_pause_poll_ms = s->last_active_ms;
    s->last_input_ms = 0;          // no pending ldisc drain to wait out
    s->deadline_ms = 0;            // deadline is not what's under test

    // Same shape as the RUN handler: begin marker (split-quoted so the echoed
    // wrapper never matches), the command, the end sentinel.
    s->begin_len = gen_begin_sentinel(s->begin_sentinel, sizeof s->begin_sentinel);
    s->draining_begin = s->begin_len > 0;
    s->begin_dropped = 0;
    char wrapped[16384];
    int wn = snprintf(wrapped, sizeof wrapped,
        "stty icanon; printf '\\n__BRIDGE_''%s\\n'; { %s\n}; __RC=$?; printf '\\n%s:%%d\\n' \"$__RC\"\n",
        s->begin_sentinel + 9, cmd, s->sentinel);
    assert(wn > 0 && (size_t)wn < sizeof wrapped);
    (void)bridge_pty_set_canon(&s->pty, 0);   // as the RUN handler does
    assert(bridge_pty_write_all(&s->pty, wrapped, (size_t)wn) == 0);

    for (int waited = 0; waited < budget_ms && !g_done && !g_parked; waited += 20) {
        struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
        poll(&pfd, 1, 20);
        service_sessions(e);
    }
}

// Answer whatever is waiting and drain to step_done, so the next case starts clean.
static void settle(edge_t *e, session_t *s, const char *reply) {
    bridge_pty_write_all(&s->pty, reply, strlen(reply));
    s->parked = 0;
    for (int i = 0; i < 200 && s->state == SESS_RUNNING; i++) {
        struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
        poll(&pfd, 1, 20);
        service_sessions(e);
    }
}

static int failures;
static void expect(const char *label, int parked_want, int done_want) {
    int ok = (g_parked > 0) == parked_want && (g_done > 0) == done_want;
    printf("%s [%-32s] parked=%d done=%d pwd=%d\n", ok ? "ok  " : "FAIL", label, g_parked, g_done, g_pwd);
    if (!ok) failures++;
}

int main(void) {
    g_max_sessions = 4;
    edge_t *e = calloc(1, sizeof *e);
    assert(e);
    e->sessions = calloc((size_t)g_max_sessions, sizeof *e->sessions);
    assert(e->sessions);
    e->noise.handshake_done = 1;  // send_json's gate; the send itself is shimmed

    session_t *s = &e->sessions[0];
    // no_echo=0 mirrors a real RUN closely enough; the password flag comes
    // from the prompt text, not from echo (see output_tail_is_prompt).
    assert(bridge_pty_spawn(&s->pty, "/bin/sh", NULL, /*no_echo=*/0) == 0);
    s->active = 1;
    s->state = SESS_IDLE;
    snprintf(s->session_id, sizeof s->session_id, "00000000-0000-4000-8000-000000000000");

    // Quiet but healthy: silent for seconds, then exits. The npm/curl/sleep shape.
    run_step(e, s, "echo start; sleep 3; echo end", 0, 8000);
    expect("sleep 3 completes", 0, 1);

    // Silence that follows a *finished* status line — npm's registry fetch.
    run_step(e, s, "printf 'fetching registry...\\n'; sleep 3; echo ok", 0, 8000);
    expect("status line then silence", 0, 1);

    // A genuine question: cursor left mid-line on a prompt.
    run_step(e, s, "printf 'Continue? [y/N] '; read a; echo got=$a", 0, 6000);
    expect("visible question parks", 1, 0);
    settle(e, s, "y\n");

    // A password prompt: the wording is what marks it secret.
    run_step(e, s, "printf 'Password: '; stty -echo; read a; stty echo; echo got=$a", 0, 6000);
    expect("password prompt parks", 1, 0);
    if (g_pwd == 0) { printf("FAIL [passwordPrompt flag not set]\n"); failures++; }
    settle(e, s, "x\n");

    // One long line, as every tool install is. Canonical mode caps a line at
    // MAX_CANON (1024 macOS / 4096 Linux) and drops the rest with a BEL — the
    // shell then never sees the newline and the step "fails to deliver".
    {
        static char big[8192];
        int n = snprintf(big, sizeof big, "echo ");
        while (n < 6000) big[n++] = 'x';
        n += snprintf(big + n, sizeof big - (size_t)n, " | wc -c | tr -d ' '");
        run_step(e, s, big, 1, 30000);
        expect("6kB command line delivered", 0, 1);
    }

    // A parked step gets canonical mode back: ^D must release `cat`'s read.
    run_step(e, s, "printf 'paste, then ^D: '; cat >/dev/null; echo eof", 0, 30000);
    expect("cat parks", 1, 0);
    settle(e, s, "\x04");
    if (s->state == SESS_RUNNING) { printf("FAIL [^D did not release parked cat]\n"); failures++; }
    else printf("ok   [%-32s]\n", "^D releases parked cat");

    // Deadline park, then a resume re-arms it. A prompt the probe can't see
    // (`read` from a pipe-less redirect keeps it off the tty: `cat` waits on
    // a fifo) must park at the deadline, and park again after an empty
    // INPUT (peek) with timeoutMs — which must write nothing to the PTY.
    {
        run_step(e, s, "mkfifo /tmp/tp_fifo.$$ 2>/dev/null; cat /tmp/tp_fifo.$$; rm -f /tmp/tp_fifo.$$", 0, 1);
        s->deadline_ms = monotonic_ms() + 300;
        for (int w = 0; w < 3000 && !g_parked; w += 20) {
            struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
            poll(&pfd, 1, 20); service_sessions(e);
        }
        expect("deadline parks", 1, 0);
        g_parked = 0;
        char peek[160];
        int pn = snprintf(peek, sizeof peek, "{\"type\":\"input\",\"sessionId\":\"%s\",\"data\":\"\",\"timeoutMs\":300}", s->session_id);
        handle_command(e, peek, (size_t)pn);
        if (s->deadline_ms == 0) { printf("FAIL [peek did not re-arm deadline]\n"); failures++; }
        for (int w = 0; w < 3000 && !g_parked; w += 20) {
            struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
            poll(&pfd, 1, 20); service_sessions(e);
        }
        expect("peek re-parks at deadline", 1, 0);
        bridge_pty_write_all(&s->pty, "\x03", 1);   // ^C the cat
        settle(e, s, "");
    }

    // stdinWaiter names the process holding the prompt even when its output
    // went to /dev/null: the leaf of the shell's process tree. Mirrors
    // apt-get → dpkg → debconf → tzdata.config with a sh → sh → cat chain.
    {
        run_step(e, s, "sh -c 'sh -c \"exec cat -A\"' >/dev/null", 0, 3000);
        if (!g_parked) {
            // Probe may be blind here (6.x container); force the park via deadline.
            s->deadline_ms = monotonic_ms() + 300;
            for (int w = 0; w < 3000 && !g_parked; w += 20) {
                struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
                poll(&pfd, 1, 20); service_sessions(e);
            }
        }
        expect("redirected prompt parks", 1, 0);
#ifdef __linux__
        if (!strstr(g_waiter, "\u2514 cat -A  ")) {
            failures++; fprintf(stderr, "FAIL stdinWaiter: got:\n%s\n", g_waiter);
        } else printf("ok   stdinWaiter:\n%s\n", g_waiter);
#endif
        bridge_pty_write_all(&s->pty, "\x03", 1);
        settle(e, s, "");
    }

    // A line-editing REPL waits in pselect6/epoll, not a tty read(): weak
    // probe signal, parks only with a prompt-shaped tail + OPAQUE_QUIET_MS.
    if (system("python3 -c 1 >/dev/null 2>&1") == 0) {
        int64_t t0 = monotonic_ms();
        run_step(e, s, "python3 -q -i -c 'print(1)'", 0, 8000);
        expect("python REPL parks", 1, 0);
        if (g_parked) printf("     parked after %lld ms\n", (long long)(monotonic_ms() - t0));
        settle(e, s, "\x04");
    } else printf("skip [python REPL parks: no python3]\n");

    // The same poll()-sleep WITHOUT a prompt (a download, a build waiting on
    // a socket) must run to completion, not park.
    run_step(e, s, "printf 'downloading...\\n'; python3 -c 'import select; select.select([],[],[],4)' 2>/dev/null || sleep 4; echo done", 0, 9000);
    expect("silent poll-wait completes", 0, 1);

    // noInput: not even a real prompt may park — the caller has nobody to ask.
    run_step(e, s, "printf 'Continue? [y/N] '; read a", 1, 3000);
    expect("noInput never parks", 0, 0);
    settle(e, s, "\n");

    bridge_pty_signal(&s->pty, 9);
    bridge_pty_close(&s->pty);
    if (failures) { fprintf(stderr, "%d case(s) failed\n", failures); return 1; }
    printf("all park cases passed\n");
    return 0;
}
