// RUN command bytes reach the shell exactly as sent (POSIX).
//
// The wrapper is typed into a PTY, so before the octal-literal delivery
// (sh_octal_lit in main.c) the line discipline rewrote the command once the
// wrapper's `stty icanon` ran: a heredoc's CRLF arrived as LF LF, `\x03`
// killed the step, `\x04` vanished, and an unterminated quote hung the step
// until its timeout. Each case feeds a real RUN frame through handle_command
// and reads the result back from the shell — on dash and on bash.
//
// Includes main.c (Noise send shimmed, entry renamed). Build+run: make test-run-bytes
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_out[512 * 1024];
static size_t g_out_len;
static int  g_done, g_code;
static char g_error[256];

static int test_capture(const char *json, size_t len);
#define noise_ws_send bridge_test_noise_send
#define bridge_main bridge_main_unused
#include "../main.c"
#undef main

int bridge_test_noise_send(noise_ws_t *n, ws_t *w, const uint8_t *pt, size_t pt_len) {
    (void)n; (void)w;
    return test_capture((const char *)pt, pt_len);
}

static int test_capture(const char *json, size_t len) {
    const char *type = NULL; size_t type_len = 0;
    if (!json_get_str(json, len, "type", &type, &type_len)) return 0;
    if (type_len == 9 && memcmp(type, "step_done", 9) == 0) {
        long c = -1; json_get_long(json, len, "exitCode", &c);
        g_code = (int)c; g_done = 1; return 0;
    }
    if (type_len == 5 && memcmp(type, "error", 5) == 0) {
        const char *c = NULL; size_t c_len = 0;
        if (json_get_str(json, len, "code", &c, &c_len) && c_len < sizeof g_error) {
            memcpy(g_error, c, c_len); g_error[c_len] = '\0';
        }
        return 0;
    }
    if (!(type_len == 6 && memcmp(type, "output", 6) == 0)) return 0;
    const char *data = NULL; size_t data_len = 0;
    assert(json_get_str(json, len, "data", &data, &data_len));
    g_out_len += b64_decode(data, data_len, g_out + g_out_len, sizeof g_out - g_out_len);
    return 0;
}

static const char *SID = "00000000-0000-4000-8000-000000000000";

// One RUN of `cmd` (cmd_len raw bytes) on the persistent session; pumps the
// loop until step_done or ~10 s. Returns 1 when the step settled.
static int run_cmd(edge_t *e, const char *cmd, size_t cmd_len) {
    static char b64[400 * 1024], frame[420 * 1024];
    size_t bn = b64_encode((const uint8_t *)cmd, cmd_len, b64, sizeof b64);
    assert(bn > 0 || cmd_len == 0);
    b64[bn] = '\0';
    int fn = snprintf(frame, sizeof frame,
        "{\"type\":\"run\",\"sessionId\":\"%s\",\"blockId\":\"rpc-1\",\"cmdB64\":\"%s\","
        "\"timeoutMs\":10000,\"output\":\"raw\"}", SID, b64);
    assert(fn > 0 && (size_t)fn < sizeof frame);
    g_out_len = 0; g_done = 0; g_code = -1; g_error[0] = '\0';
    assert(handle_command(e, frame, (size_t)fn) == 0);
    session_t *s = find_session(e, SID, strlen(SID));
    assert(s);
    for (int i = 0; i < 500 && !g_done && s->state == SESS_RUNNING; i++) {
        struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
        poll(&pfd, 1, 20);
        service_sessions(e);
    }
    g_out[g_out_len] = '\0';
    return g_done;
}

static int g_fails;
static const char *g_shell;

static void check(const char *label, int ok) {
    printf("%s [%-9s] %s\n", ok ? "ok  " : "FAIL", g_shell, label);
    if (!ok) {
        g_fails++;
        fprintf(stderr, "  code=%d error=[%s] out(%zu)=", g_code, g_error, g_out_len);
        for (size_t i = 0; i < g_out_len && i < 400; i++) {
            unsigned char c = (unsigned char)g_out[i];
            if (c >= 32 && c < 127) fputc(c, stderr); else fprintf(stderr, "\\x%02x", c);
        }
        fputc('\n', stderr);
    }
}

static int has(const char *needle) { return memmem(g_out, g_out_len, needle, strlen(needle)) != NULL; }

#define RUN(lit) run_cmd(e, lit, sizeof(lit) - 1)

static void suite(edge_t *e) {
    // od -An -tx1: the exact bytes the command received, as hex.
    check("heredoc keeps CRLF",
          RUN("od -An -tx1 <<'E'\na\r\nb\nE") && g_code == 0 && has("61 0d 0a 62 0a"));
    check("heredoc keeps ^C ^D DEL ^U ^W (no signal, no EOF)",
          RUN("od -An -tx1 <<'E'\n\x03\x04\x7f\x15\x17\nE") && g_code == 0 && has("03 04 7f 15 17 0a"));
    check("quotes, backslash, percent, $ and UTF-8 pass through",
          RUN("printf '%s\\n' \"it's \\\\ 100% $((6*7)) ő\"") && g_code == 0 && has("it's \\ 100% 42 \xc5\x91"));
    check("command starting with '-' is not an option",
          RUN("-definitely-not-a-cmd 2>/dev/null; echo rc=$?") && has("rc=127"));
    // Every byte 0x01-0xff inside a quoted heredoc, compared as hex.
    {
        char cmd[400], want[1100]; size_t n = 0, w = 0;
        n += (size_t)sprintf(cmd, "od -An -v -tx1 <<'E' | tr -d ' \\n'\n");
        for (int b = 1; b < 256; b++) { cmd[n++] = (char)b; w += (size_t)sprintf(want + w, "%02x", b); }
        n += (size_t)sprintf(cmd + n, "\nE");
        w += (size_t)sprintf(want + w, "0a");
        check("all bytes 0x01-0xff round-trip", run_cmd(e, cmd, n) && g_code == 0 && has(want));
    }
    check("exit code survives", RUN("echo x; exit 7") && g_code == 7 && has("x"));
    check("set -e stops at the failure", RUN("set -e; false; echo NOT") && g_code == 1 && !has("NOT"));
    check("functions and case", RUN("f(){ case $1 in a) echo hit;; esac; }; f a") && has("hit"));
    check("multi-line script with trailing newlines", RUN("echo one\necho two\n\n\n") && has("one") && has("two"));
    check("unterminated quote fails fast instead of hanging",
          RUN("echo 'unterminated") && g_code != 0 && g_code != -1);
    check("empty command", RUN("") && g_code == 0);

    // ~48 KB of commands with UTF-8 on every line: ~4x on the wire.
    static char big[64 * 1024]; size_t n = 0;
    for (int i = 0; i < 1000; i++) n += (size_t)sprintf(big + n, ": %04d padding padding ő\n", i);
    n += (size_t)sprintf(big + n, "echo big-done");
    check("48 KB command with UTF-8", run_cmd(e, big, n) && g_code == 0 && has("big-done"));

    // Persistent shell is still healthy after all of the above.
    check("session still usable", RUN("echo alive") && g_code == 0 && has("alive"));
}

int main(void) {
    const char *shells[] = { "/bin/sh", "/bin/bash" };
    for (size_t i = 0; i < sizeof shells / sizeof *shells; i++) {
        g_shell = shells[i];
        if (access(g_shell, X_OK) != 0) { printf("skip [%s] not installed\n", g_shell); continue; }
        g_max_sessions = 4;
        edge_t *e = calloc(1, sizeof *e);
        assert(e);
        e->sessions = calloc((size_t)g_max_sessions, sizeof *e->sessions);
        assert(e->sessions);
        e->noise.handshake_done = 1;
        session_t *s = &e->sessions[0];
        assert(bridge_pty_spawn(&s->pty, g_shell, NULL, /*no_echo=*/1) == 0);
        s->active = 1;
        s->state = SESS_IDLE;
        s->one_shot = 0;
        snprintf(s->session_id, sizeof s->session_id, "%s", SID);
        suite(e);
        bridge_pty_close(&s->pty);
        free(e->sessions);
        free(e);
    }
    if (g_fails) { fprintf(stderr, "%d failure(s)\n", g_fails); return 1; }
    printf("all ok\n");
    return 0;
}
