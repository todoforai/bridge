// Per-step begin drain: on Windows/ConPTY (busybox, cmd) the console echoes
// the wrapper line and the shell prints a prompt with no host-side ECHO
// toggle, so every RUN wrapper starts with `printf '\n<begin>\n'` and all
// output is DROPPED until that begin sentinel's line has passed.
//
// This test simulates the ConPTY condition on POSIX by spawning with echo ON
// (no_echo=0): the echoed init + echoed wrapper must be fully drained/absent
// and the step output must be byte-exact anyway.
//
// Includes main.c directly (renaming its main + stubbing the Noise send) so
// the real forward_pty_output drain path is exercised. Build+run: make test-initdrain

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_capture(const char *json, size_t len);

#define noise_ws_send bridge_test_noise_send
#define bridge_main bridge_main_unused
#include "../main.c"
#undef main

static char   g_out[1 << 20];
static size_t g_out_len;
static int    g_step_done;

int bridge_test_noise_send(noise_ws_t *n, ws_t *w, const uint8_t *pt, size_t pt_len) {
    (void)n; (void)w;
    return test_capture((const char *)pt, pt_len);
}

static int test_capture(const char *json, size_t len) {
    const char *type = NULL; size_t type_len = 0;
    if (!json_get_str(json, len, "type", &type, &type_len)) return 0;
    if (type_len == 9 && memcmp(type, "step_done", 9) == 0) { g_step_done = 1; return 0; }
    if (!(type_len == 6 && memcmp(type, "output", 6) == 0)) return 0;
    const char *data = NULL; size_t data_len = 0;
    assert(json_get_str(json, len, "data", &data, &data_len));
    size_t dn = b64_decode(data, data_len, g_out + g_out_len, sizeof g_out - g_out_len);
    g_out_len += dn;
    return 0;
}

// ── Deterministic scanner tests (no PTY): drive begin_drain_scan byte-by-byte ──

// Feed `data` into the drain in `chunk`-sized pieces; returns final tail as a
// string in out (assumes drain completes) and 1 if drain ended.
static int feed_drain(session_t *s, const char *data, size_t chunk, char *out, size_t out_cap) {
    size_t len = strlen(data), off = 0;
    int done = 0;
    while (off < len) {
        size_t n = len - off < chunk ? len - off : chunk;
        tail_append(s, (const uint8_t *)data + off, n);
        off += n;
        if (!done) done = begin_drain_scan(s);
        // Once done, further bytes just accumulate in tail_buf (caller's job);
        // keep appending to simulate the RUN parser's buffer.
    }
    size_t cl = s->tail_len < out_cap - 1 ? s->tail_len : out_cap - 1;
    memcpy(out, s->tail_buf, cl);
    out[cl] = '\0';
    return done;
}

static session_t *mk_drain_sess(void) {
    static session_t s;
    memset(&s, 0, sizeof s);
    snprintf(s.session_id, sizeof s.session_id, "00000000-0000-4000-8000-000000000000");
    snprintf(s.begin_sentinel, sizeof s.begin_sentinel, "__BRIDGE_BEGIN_cafe__");
    s.begin_len = strlen(s.begin_sentinel);
    s.draining_begin = 1;
    return &s;
}

static int scanner_cases(void) {
    int fails = 0;
    char out[4096];

    // Marker + VT escapes between marker and newline (ConPTY decoration),
    // then real output — split at EVERY chunk size to cover read boundaries.
    const char *vt = "prompt$ echoed line\r\n__BRIDGE_BEGIN_cafe__\x1b[?25h\x1b[0m\r\nREAL\r\n";
    for (size_t chunk = 1; chunk <= strlen(vt); chunk++) {
        session_t *s = mk_drain_sess();
        int done = feed_drain(s, vt, chunk, out, sizeof out);
        if (!done || strcmp(out, "REAL\r\n") != 0) {
            fprintf(stderr, "[scanner-vt chunk=%zu] FAIL: done=%d out=%s\n", chunk, done, out);
            fails++; break;
        }
    }
    if (!fails) fprintf(stderr, "[scanner-vt] OK (all chunk splits)\n");

    // Echoed split-quoted copy must NOT terminate the drain early.
    {
        session_t *s = mk_drain_sess();
        const char *echoed = "$ printf '\\n__BRIDGE_''READY_cafe__\\n'\r\n__BRIDGE_BEGIN_cafe__\r\nout\r\n";
        int done = feed_drain(s, echoed, 7, out, sizeof out);
        if (!done || strcmp(out, "out\r\n") != 0) {
            fprintf(stderr, "[scanner-echoed] FAIL: done=%d out=%s\n", done, out);
            fails++;
        } else fprintf(stderr, "[scanner-echoed] OK\n");
    }

    // Fail-safe: no marker ever arrives → drain gives up after BEGIN_DRAIN_MAX.
    {
        session_t *s = mk_drain_sess();
        char junk[1024]; memset(junk, 'x', sizeof junk - 1); junk[sizeof junk - 1] = '\0';
        int done = 0;
        for (int i = 0; i < 2 * (BEGIN_DRAIN_MAX / 1023) + 4 && !done; i++) {
            tail_append(s, (const uint8_t *)junk, 1023);
            done = begin_drain_scan(s);
        }
        if (!done || s->draining_begin) {
            fprintf(stderr, "[scanner-failsafe] FAIL: drain never gave up\n");
            fails++;
        } else fprintf(stderr, "[scanner-failsafe] OK\n");
    }
    return fails;
}

// One case: spawn echo-ON shell, send init line + wrapped cmd back-to-back
// (exactly like the RUN handler), drive to step_done, check captured output.
static int run_case(const char *label, const char *cmd, const char *expect_out) {
    g_out_len = 0; g_step_done = 0;

    edge_t *e = calloc(1, sizeof *e);
    assert(e);
    e->sessions = calloc((size_t)g_max_sessions, sizeof *e->sessions);
    assert(e->sessions);
    e->noise.handshake_done = 1;

    session_t *s = &e->sessions[0];
    // no_echo=0 ⇒ the PTY echoes every input line, like ConPTY does.
    assert(bridge_pty_spawn(&s->pty, "/bin/sh", NULL, /*no_echo=*/0) == 0);
    s->active = 1;
    snprintf(s->session_id, sizeof s->session_id, "00000000-0000-4000-8000-000000000000");

    // Best-effort echo suppression, exactly like the RUN handler.
    char init_line[96];
    size_t in_n = build_init_line(init_line, sizeof init_line);
    assert(in_n > 0);
    assert(bridge_pty_write_all(&s->pty, init_line, in_n) == 0);

    // Wrapped step, queued immediately behind the init (no waiting).
    s->sentinel_len = gen_sentinel(s->sentinel, sizeof s->sentinel);
    s->begin_len = gen_begin_sentinel(s->begin_sentinel, sizeof s->begin_sentinel);
    assert(s->begin_len > 0);
    s->draining_begin = 1;
    s->begin_dropped = 0;
    s->state = SESS_RUNNING;
    s->tail_len = 0;
    s->one_shot = 0;
    ob_resolve(&s->ob, "raw", 3);
    char wrapped[4096];
    int wn = snprintf(wrapped, sizeof wrapped,
        "printf '\\n__BRIDGE_''%s\\n'; { %s\n}; __RC=$?; printf '\\n%s:%%d\\n' \"$__RC\"\n",
        s->begin_sentinel + 9, cmd, s->sentinel);
    assert(wn > 0 && (size_t)wn < sizeof wrapped);
    assert(bridge_pty_write_all(&s->pty, wrapped, (size_t)wn) == 0);

    for (int i = 0; i < 500 && s->state == SESS_RUNNING; i++) {
        struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
        poll(&pfd, 1, 20);
        service_sessions(e);
    }

    int fail = 0;
    if (s->state == SESS_RUNNING || !g_step_done) {
        fprintf(stderr, "[%s] FAIL: step never completed (drain swallowed the step sentinel?)\n", label);
        fail = 1;
    } else if (g_out_len != strlen(expect_out) || memcmp(g_out, expect_out, g_out_len) != 0) {
        fprintf(stderr, "[%s] FAIL: output mismatch (want %zub, got %zub)\n  got: ",
                label, strlen(expect_out), g_out_len);
        for (size_t i = 0; i < g_out_len && i < 300; i++) {
            unsigned char c = (unsigned char)g_out[i];
            if (c >= 32 && c < 127) fputc(c, stderr); else fprintf(stderr, "\\x%02x", c);
        }
        fputc('\n', stderr);
        fail = 1;
    } else if (memmem(g_out, g_out_len, s->begin_sentinel, s->begin_len) ||
               memmem(g_out, g_out_len, "stty -echo", 10) ||
               memmem(g_out, g_out_len, "__RC=", 5) ||
               memmem(g_out, g_out_len, "PS1=", 4)) {
        fprintf(stderr, "[%s] FAIL: init/echo leaked into output\n", label);
        fail = 1;
    } else {
        fprintf(stderr, "[%s] OK (out=%zub)\n", label, g_out_len);
    }

    bridge_pty_close(&s->pty);
    free(e->sessions);
    free(e);
    return fail;
}

// vt_strip: conhost injects escapes at arbitrary offsets — even inside the
// sentinel — so the stripper must remove them across read() boundaries and
// leave every printable byte (and \r\n\t) untouched.
static int vt_cases(void) {
    static const struct { const char *in, *want; } cases[] = {
        // ESC split INSIDE the sentinel (the real ConPTY failure).
        { "__BRIDGE_STEP_485cc738f\x1b[?25l4ef35d__:0\r\n", "__BRIDGE_STEP_485cc738f4ef35d__:0\r\n" },
        { "hello\x1b[19;1H\r\n",        "hello\r\n" },        // CSI cursor move
        { "a\x1b]0;title\ab",            "ab" },               // OSC + BEL
        { "a\x1b]0;title\x1b\\b",        "ab" },               // OSC + ST
        { "a\x1b(Bb",                    "ab" },               // charset select
        { "a\x1b=b",                     "ab" },               // 2-byte ESC seq
        { "plain\ttext\r\n",             "plain\ttext\r\n" },  // nothing to strip
    };
    int fails = 0;
    for (size_t c = 0; c < sizeof cases / sizeof *cases; c++) {
        // Every chunk size: a sequence straddling reads must still vanish.
        size_t len = strlen(cases[c].in);
        for (size_t chunk = 1; chunk <= len; chunk++) {
            vt_state_t st = VT_TEXT;
            char out[256]; size_t out_len = 0;
            for (size_t off = 0; off < len; off += chunk) {
                size_t take = len - off < chunk ? len - off : chunk;
                uint8_t tmp[256];
                memcpy(tmp, cases[c].in + off, take);
                size_t kept = vt_strip(&st, tmp, take);
                memcpy(out + out_len, tmp, kept);
                out_len += kept;
            }
            out[out_len] = '\0';
            if (strcmp(out, cases[c].want) != 0) {
                fprintf(stderr, "[vt-strip case=%zu chunk=%zu] FAIL: got '%s' want '%s'\n",
                        c, chunk, out, cases[c].want);
                fails++;
                break;
            }
        }
    }
    if (!fails) fprintf(stderr, "[vt-strip] OK (all cases, all chunk splits)\n");
    return fails;
}

int main(void) {
    g_max_sessions = 4;
    int fails = 0;
    fails += vt_cases();
    fails += scanner_cases();
    fails += run_case("echo-on-simple", "echo hello",     "hello\r\n");
    fails += run_case("echo-on-multi",  "echo a; echo b", "a\r\nb\r\n");
    fails += run_case("echo-on-empty",  "true",           "");
    // Output that contains the BEGIN prefix must survive (drain is over by then).
    fails += run_case("begin-lookalike", "printf '__BRIDGE_BEGIN_fake__\\n'", "__BRIDGE_BEGIN_fake__\r\n");
    if (fails) fprintf(stderr, "\n%d test(s) failed\n", fails);
    else       fprintf(stderr, "\nall init-drain tests passed\n");
    return fails ? 1 : 0;
}
