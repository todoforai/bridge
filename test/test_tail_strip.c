// Trailing `| tail -N` strip: the bridge drops the tail stage, streams the
// prefix into its rolling tail and emits the last N lines itself — so a step
// that parks mid-way shows progress instead of "(no output)", and the exit
// code is the command's, not tail's.
//
// Includes main.c (Noise send shimmed, entry renamed). Build+run: make test-tail-strip
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define noise_ws_send bridge_test_noise_send
#define bridge_main bridge_main_unused
#include "../main.c"
#undef main

static char   g_out[1 << 20];
static size_t g_out_len;
static int    g_exit_code = -999, g_parked;
static int failures;

int bridge_test_noise_send(noise_ws_t *n, ws_t *w, const uint8_t *pt, size_t pt_len) {
    (void)n; (void)w;
    const char *json = (const char *)pt; size_t len = pt_len;
    const char *type = NULL; size_t type_len = 0;
    if (!json_get_str(json, len, "type", &type, &type_len)) return 0;
    if (type_len == 9 && memcmp(type, "step_done", 9) == 0) {
        long rc = -999; json_get_long(json, len, "exitCode", &rc); g_exit_code = (int)rc;
    } else if (type_len == 19 && memcmp(type, "step_awaiting_input", 19) == 0) {
        g_parked++;
    } else if (type_len == 6 && memcmp(type, "output", 6) == 0) {
        const char *data = NULL; size_t data_len = 0;
        assert(json_get_str(json, len, "data", &data, &data_len));
        g_out_len += b64_decode(data, data_len, g_out + g_out_len, sizeof g_out - g_out_len);
    }
    return 0;
}

#define CHECK(c, l) do { int ok_ = (c); printf("  %-60s %s\n", l, ok_ ? "ok" : "FAIL"); if (!ok_) failures++; } while (0)

// ── Parser ──
static void parse_case(const char *cmd, long want_lines, const char *want_prefix) {
    size_t plen = 0;
    long got = strip_trailing_tail(cmd, strlen(cmd), &plen);
    int ok = got == want_lines && (want_lines == 0 || (plen == strlen(want_prefix) && memcmp(cmd, want_prefix, plen) == 0));
    char label[160]; snprintf(label, sizeof label, "parse: %s", cmd);
    for (char *p = label; *p; p++) if (*p == '\n') *p = '~';
    CHECK(ok, label);
    if (!ok) fprintf(stderr, "    got lines=%ld prefix_len=%zu\n", got, plen);
}

// ── Live step through the real loop (mirrors test_coalesce's run_cmd) ──
static void run_step(edge_t *e, session_t *s, const char *cmd, int64_t deadline_in_ms) {
    g_out_len = 0; memset(g_out, 0, sizeof g_out); g_exit_code = -999; g_parked = 0;
    ob_resolve(&s->ob, "safe", 4);
    size_t cmd_len = strlen(cmd), plen = 0;
    long tl = strip_trailing_tail(cmd, cmd_len, &plen);
    if (tl > 0) { cmd_len = plen; ob_set_tail_lines(&s->ob, tl); }
    snprintf(s->sentinel, sizeof s->sentinel, "__BRIDGE_STEP_TAILSTRIP_TEST__");
    s->sentinel_len = strlen(s->sentinel);
    s->state = SESS_RUNNING;
    s->tail_len = 0; s->parked = 0; s->no_input = 0;
    s->one_shot = 0;
    s->deadline_ms = deadline_in_ms ? monotonic_ms() + deadline_in_ms : 0;
    char wrapped[4096];
    int wn = snprintf(wrapped, sizeof wrapped,
        "trap : INT; ( %.*s\n); __RC=$?; printf '\\n%s:%%d\\n' \"$__RC\"\n", (int)cmd_len, cmd, s->sentinel);
    assert(wn > 0 && (size_t)wn < sizeof wrapped);
    assert(bridge_pty_write_all(&s->pty, wrapped, (size_t)wn) == 0);
    for (int i = 0; i < 400 && s->state == SESS_RUNNING && !g_parked; i++) {
        struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
        poll(&pfd, 1, 20);
        service_sessions(e);
    }
}

int main(void) {
    printf("strip_trailing_tail parser\n");
    parse_case("seq 100 | tail -5", 5, "seq 100");
    parse_case("ls | tail -n 10", 10, "ls");
    parse_case("ls | tail -n10", 10, "ls");
    parse_case("ls | tail --lines=3", 3, "ls");
    parse_case("ls | tail --lines 3", 3, "ls");
    parse_case("expect /tmp/setup.exp 2>&1 | tail -60", 60, "expect /tmp/setup.exp 2>&1");
    parse_case("make 2>&1 |tail -20\n", 20, "make 2>&1");
    parse_case("make |& tail -20", 0, NULL);          // `|&` carries a redirect; fail open
    parse_case("cat f | grep x | tail -3", 3, "cat f | grep x");
    parse_case("echo \"a | tail -5\" | tail -2", 2, "echo \"a | tail -5\"");
    parse_case("echo 'x;y' | tail -1", 1, "echo 'x;y'");
    parse_case("(cd /tmp && make) 2>&1 | tail -4", 4, "(cd /tmp && make) 2>&1");
    parse_case("for i in 1 2; do echo $i; done | tail -1", 0, NULL);  // `;` at top level → untouched (fails open)
    // Untouched:
    parse_case("ls; echo hi | tail -5", 0, NULL);
    parse_case("a && b | tail -3", 0, NULL);
    parse_case("a || b | tail -3", 0, NULL);
    parse_case("a &\nb | tail -3", 0, NULL);
    parse_case("sleep 5 & tail -3", 0, NULL);
    parse_case("tail -f log", 0, NULL);
    parse_case("tail -5 file.txt", 0, NULL);
    parse_case("cat x | tail -n +5", 0, NULL);
    parse_case("cat x | tail -c 100", 0, NULL);
    parse_case("cat x | tail", 0, NULL);
    parse_case("cat x | tail -0", 0, NULL);
    parse_case("cat x | head -5", 0, NULL);
    parse_case("cat x | mytail -5", 0, NULL);
    parse_case("echo `ls | tail -1` | tail -1", 0, NULL);
    parse_case("ls # | tail -1", 0, NULL);
    parse_case("ls | tail -5 | sort", 0, NULL);
    parse_case("echo \\| tail -1", 0, NULL);          // escaped pipe is text
    parse_case("echo {; echo }; seq 3 | tail -1", 0, NULL);  // literal braces must not hide `;`
    parse_case("{ a; b; } | tail -1", 0, NULL);
    parse_case("echo $(ls; pwd) | tail -1", 1, "echo $(ls; pwd)");

    printf("live steps\n");
    g_max_sessions = 2;
    edge_t *e = calloc(1, sizeof *e);
    e->sessions = calloc((size_t)g_max_sessions, sizeof *e->sessions);
    e->noise.handshake_done = 1;
    session_t *s = &e->sessions[0];
    assert(bridge_pty_spawn(&s->pty, "/bin/sh", NULL, /*no_echo=*/1) == 0);
    s->active = 1; s->state = SESS_IDLE;
    snprintf(s->session_id, sizeof s->session_id, "00000000-0000-4000-8000-000000000000");

    // Last N lines, byte-exact.
    run_step(e, s, "seq 1 100 | tail -3", 0);
    CHECK(s->state == SESS_IDLE && strcmp(g_out, "98\n99\n100\n") == 0, "seq 100 | tail -3 → last 3 lines");
    if (strcmp(g_out, "98\n99\n100\n")) fprintf(stderr, "    got %zu bytes: [%s]\n", g_out_len, g_out);

    // Fewer lines than N → all of it.
    run_step(e, s, "printf 'a\\nb\\n' | tail -5", 0);
    CHECK(strcmp(g_out, "a\nb\n") == 0, "2 lines | tail -5 → both");
    fprintf(stderr, "    [2lines] rc=%d parked=%d out=[%s]\n", g_exit_code, g_parked, g_out);

    // Exit code is the command's, not tail's.
    run_step(e, s, "(echo x; exit 3) 2>&1 | tail -1", 0);
    CHECK(g_exit_code == 3 && strcmp(g_out, "x\n") == 0, "exit code is the prefix's (3)");
    fprintf(stderr, "    [exit3] rc=%d out=[%s]\n", g_exit_code, g_out);

    // Unterminated last line still arrives.
    run_step(e, s, "printf 'one\\ntwo' | tail -1", 0);
    CHECK(strcmp(g_out, "two") == 0, "unterminated last line");
    fprintf(stderr, "    [unterm] out=[%s]\n", g_out);

    // Untouched command behaves as before (tail runs in the shell).
    run_step(e, s, "seq 1 10 | tail -2; echo done", 0);
    CHECK(strcmp(g_out, "9\r\n10\r\ndone\r\n") == 0, "`;` chain runs tail in-shell");

    // More lines asked than the 10k tail holds → flagged, not silent.
    run_step(e, s, "seq 1 20000 | tail -5000", 0);
    CHECK(s->ob.truncated == 1 && strncmp(g_out, "[tail -5000: only the last", 26) == 0, "overflowing N → truncated + notice");
    CHECK(strstr(g_out, "\n20000\n") != NULL, "...but the end is intact");
    run_step(e, s, "seq 1 20000 | tail -3", 0);
    CHECK(s->ob.truncated == 0 && strcmp(g_out, "19998\n19999\n20000\n") == 0, "wrapped buffer, N fits → clean");

    // raw/full: untouched (tail runs in the shell, bytes as-is).
    ob_resolve(&s->ob, "raw", 3);
    CHECK(!ob_tail_strip_ok(&s->ob), "raw mode: no strip");
    ob_resolve(&s->ob, "full", 4);
    CHECK(!ob_tail_strip_ok(&s->ob), "full mode: no strip");
    ob_resolve(&s->ob, "wide", 4);
    CHECK(ob_tail_strip_ok(&s->ob), "wide mode: strip");

    // The qemu shape: a slow producer in a pipe with stderr merged — the
    // backend saw "(no output)" for 7 minutes behind `| tail -60`.
    run_step(e, s, "(echo boot; sleep 0.2; echo 'apk add' >&2; sleep 5) 2>&1 | tail -60", 600);
    CHECK(g_parked == 1 && strcmp(g_out, "boot\napk add\n") == 0, "qemu shape: park shows boot + stderr line");
    if (g_parked != 1 || strcmp(g_out, "boot\napk add\n")) fprintf(stderr, "    got parked=%d [%s]\n", g_parked, g_out);
    bridge_pty_write_all(&s->pty, "\003", 1);
    for (int i = 0; i < 100 && s->state == SESS_RUNNING; i++) {
        struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
        poll(&pfd, 1, 20);
        service_sessions(e);
    }
    CHECK(s->state == SESS_IDLE, "^C settles the parked step");

    // The point of it all: a park at the deadline shows the progress so far.
    run_step(e, s, "(i=0; while :; do i=$((i+1)); echo tick$i; sleep 0.05; done) 2>&1 | tail -2", 400);
    CHECK(g_parked == 1, "deadline parks the step");
    CHECK(g_out_len > 0 && strstr(g_out, "tick") != NULL, "parked output holds the last ticks");
    int nl = 0; for (size_t i = 0; i < g_out_len; i++) nl += g_out[i] == '\n';
    CHECK(nl == 2, "parked output is exactly N lines");
    if (nl != 2) fprintf(stderr, "    got [%s]\n", g_out);
    // Post-park, a resume delta is a fresh window: more ticks, again ≤ N lines.
    g_out_len = 0; memset(g_out, 0, sizeof g_out);
    s->parked = 0; s->deadline_ms = monotonic_ms() + 200;
    g_parked = 0;
    for (int i = 0; i < 60 && !g_parked; i++) {
        struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
        poll(&pfd, 1, 20);
        service_sessions(e);
    }
    nl = 0; for (size_t i = 0; i < g_out_len; i++) nl += g_out[i] == '\n';
    CHECK(g_parked == 1 && nl == 2, "resume window again last N lines");
    bridge_pty_write_all(&s->pty, "\003", 1);
    for (int i = 0; i < 100 && s->state == SESS_RUNNING; i++) {
        struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
        poll(&pfd, 1, 20);
        service_sessions(e);
    }

    bridge_pty_close(&s->pty);
    if (failures) { printf("%d FAILED\n", failures); return 1; }
    printf("all tests passed\n");
    return 0;
}
