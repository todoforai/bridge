// OUTPUT coalescing: a verbose RUN must ship its bytes in few, large frames
// instead of one frame per PTY read, and must not lose or reorder a byte.
//
// Includes main.c directly (renaming its main + stubbing the Noise send) so the
// real send_output_bytes/flush_output/forward_pty_output path is exercised.
// Build+run: make test-coalesce

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Capture frames instead of encrypting them onto a socket. send_json() is the
// single choke point and calls noise_ws_send, so shimming that catches all.
static int    g_frames;          // OUTPUT frames seen
static size_t g_bytes;           // decoded OUTPUT payload bytes
static char   g_out[2 * 1024 * 1024];
static size_t g_out_len;
static int    g_step_done_after;  // g_frames when step_done arrived (-1 = never)
static double g_t0;               // run start, for the age-flush bound
static double g_first_frame_ms;   // when the first OUTPUT frame was emitted

static int test_capture(const char *json, size_t len);

static double test_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

// Object-like renames so both the header prototype and main.c's call site move
// to our shim; main.c's own entry point is compiled out of the way.
#define noise_ws_send bridge_test_noise_send
#define bridge_main bridge_main_unused
#include "../main.c"
#undef main

int bridge_test_noise_send(noise_ws_t *n, ws_t *w, const uint8_t *pt, size_t pt_len) {
    (void)n; (void)w;
    return test_capture((const char *)pt, pt_len);
}

// Decode one captured frame: OUTPUT payloads append to g_out, step_done marks
// the terminal position so we can assert nothing is streamed after it.
static int test_capture(const char *json, size_t len) {
    const char *type = NULL; size_t type_len = 0;
    if (!json_get_str(json, len, "type", &type, &type_len)) return 0;
    if (type_len == 9 && memcmp(type, "step_done", 9) == 0) { g_step_done_after = g_frames; return 0; }
    if (!(type_len == 6 && memcmp(type, "output", 6) == 0)) return 0;

    const char *data = NULL; size_t data_len = 0;
    assert(json_get_str(json, len, "data", &data, &data_len));
    size_t dn = b64_decode(data, data_len, g_out + g_out_len, sizeof g_out - g_out_len);
    assert(dn > 0);
    g_out_len += dn;
    g_bytes += dn;
    if (g_frames == 0) g_first_frame_ms = test_now_ms() - g_t0;
    g_frames++;
    return 0;
}

// Drive a one-shot RUN to completion the way the main loop does.
static void run_cmd(edge_t *e, session_t *s, const char *cmd, const char *mode) {
    ob_resolve(&s->ob, mode, strlen(mode));
    snprintf(s->sentinel, sizeof s->sentinel, "__BRIDGE_STEP_COALESCE_TEST__");
    s->sentinel_len = strlen(s->sentinel);
    s->state = SESS_RUNNING;
    s->tail_len = 0;
    s->one_shot = 0;  // keep the PTY so a second case can reuse the slot

    char wrapped[4096];
    int wn = snprintf(wrapped, sizeof wrapped,
        "{ %s\n}; __RC=$?; printf '\\n%s:%%d\\n' \"$__RC\"\n", cmd, s->sentinel);
    assert(wn > 0 && (size_t)wn < sizeof wrapped);
    assert(bridge_pty_write_all(&s->pty, wrapped, (size_t)wn) == 0);

    for (int i = 0; i < 2000 && s->state == SESS_RUNNING; i++) {
        struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
        poll(&pfd, 1, 20);
        service_sessions(e);
    }
    assert(s->state == SESS_IDLE);  // sentinel seen → step_done
}

static void reset_capture(void) {
    g_frames = 0; g_bytes = 0; g_out_len = 0; g_step_done_after = -1;
    g_first_frame_ms = -1; g_t0 = test_now_ms();
}

int main(void) {
    g_max_sessions = 4;
    edge_t *e = calloc(1, sizeof *e);
    assert(e);
    e->sessions = calloc((size_t)g_max_sessions, sizeof *e->sessions);
    assert(e->sessions);
    e->noise.handshake_done = 1;  // send_json's gate; the send itself is shimmed

    session_t *s = &e->sessions[0];
    assert(bridge_pty_spawn(&s->pty, "/bin/sh", NULL, /*no_echo=*/1) == 0);
    s->active = 1;
    s->state = SESS_IDLE;
    snprintf(s->session_id, sizeof s->session_id, "00000000-0000-4000-8000-000000000000");

    // ── Verbose output: few frames, byte-exact, all before step_done ──
    const int N = 3000;
    reset_capture();
    char cmd[128];
    snprintf(cmd, sizeof cmd, "i=1; while [ $i -le %d ]; do echo line$i; i=$((i+1)); done", N);
    run_cmd(e, s, cmd, "raw");

    size_t expect_len = 0;
    char *expect = malloc(1 << 20);
    assert(expect);
    for (int i = 1; i <= N; i++)
        expect_len += (size_t)snprintf(expect + expect_len, (1 << 20) - expect_len, "line%d\r\n", i);
    if (g_out_len != expect_len || memcmp(g_out, expect, expect_len) != 0) {
        fprintf(stderr, "[verbose] output mismatch: got %zu bytes, want %zu\n", g_out_len, expect_len);
        return 1;
    }
    // Unbatched this is one frame per 4096-byte read (4 frames per 16KB batch).
    size_t max_frames = g_bytes / OUT_FLUSH_BYTES + 3;
    if ((size_t)g_frames > max_frames) {
        fprintf(stderr, "[verbose] too many frames: %d for %zu bytes (max %zu)\n",
                g_frames, g_bytes, max_frames);
        return 1;
    }
    if (g_step_done_after != g_frames) {
        fprintf(stderr, "[verbose] output streamed after step_done (%d of %d frames before)\n",
                g_step_done_after, g_frames);
        return 1;
    }
    printf("[verbose] OK (%zu bytes in %d frames, step_done last)\n", g_bytes, g_frames);
    free(expect);

    // ── Truncating mode: the 10k tail is one emission > b64_buf's old cap ──
    reset_capture();
    run_cmd(e, s, "i=1; while [ $i -le 4000 ]; do echo abcdefghij; i=$((i+1)); done", "safe");
    if (g_out_len < OB_STREAM_FIRST + OB_STREAM_LAST) {
        fprintf(stderr, "[truncated] head+tail not fully delivered: %zu bytes\n", g_out_len);
        return 1;
    }
    if (!memmem(g_out, g_out_len, "[truncated", 10)) {
        fprintf(stderr, "[truncated] notice missing\n");
        return 1;
    }
    if (g_step_done_after != g_frames) {
        fprintf(stderr, "[truncated] tail arrived after step_done\n");
        return 1;
    }
    printf("[truncated] OK (%zu bytes in %d frames, notice+tail before step_done)\n", g_bytes, g_frames);

    // ── Slow trickle: age-based flush ships the first line without waiting ──
    // The line must exceed sentinel_len so forward_pty_output's sentinel
    // hold-back doesn't park it in tail_buf (that's not the coalescer).
    reset_capture();
    run_cmd(e, s, "echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; sleep 0.6; echo drop", "raw");
    if (g_frames < 2) {
        fprintf(stderr, "[trickle] first line did not flush on the timer, got %d frame(s)\n", g_frames);
        return 1;
    }
    // Bound the age trigger itself: OUT_FLUSH_MS plus shell warmup and a couple
    // of loop ticks. A regression to a much slower timer must fail here.
    if (g_first_frame_ms > OUT_FLUSH_MS + 250) {
        fprintf(stderr, "[trickle] first frame took %.0fms (want ≤ %dms + slack)\n",
                g_first_frame_ms, OUT_FLUSH_MS);
        return 1;
    }
    printf("[trickle] OK (%d frames, first at %.0fms)\n", g_frames, g_first_frame_ms);

    // ── Short prompt, no newline: must ship before the step ends ──
    // `[sudo] password for six: ` is 25 bytes < sentinel_len. A flat
    // (sentinel_len-1) hold-back kept it in tail_buf, so a step parked on a
    // password prompt surfaced as "(no output)". Only a real sentinel prefix
    // may be held.
    reset_capture();
    run_cmd(e, s, "printf 'Password: '; sleep 0.6; echo", "raw");
    if (g_frames < 2 || g_first_frame_ms > OUT_FLUSH_MS + 250) {
        fprintf(stderr, "[prompt] short prompt held back: %d frame(s), first at %.0fms\n",
                g_frames, g_first_frame_ms);
        return 1;
    }
    printf("[prompt] OK (%d frames, first at %.0fms)\n", g_frames, g_first_frame_ms);

    // ── A genuine sentinel prefix at the tail is still held (and matched) ──
    reset_capture();
    run_cmd(e, s, "printf '__BRIDGE_STEP_'; sleep 0.3; printf 'x\\n'", "raw");
    if (g_out_len != 17 || memcmp(g_out, "__BRIDGE_STEP_x\r\n", 17) != 0) {
        fprintf(stderr, "[prefix] got %zu bytes: %.*s\n", g_out_len, (int)g_out_len, g_out);
        return 1;
    }
    printf("[prefix] OK (prefix held, then emitted intact)\n");

    // ── Spinner redraws: the output policy counts what a terminal shows ──
    // 4000 × "⠙<CSI 1G><CSI 0K>" = ~44KB of raw redraw frames, then the real
    // log. Raw accounting would fill the 10k head with spinner junk, mark
    // the step truncated and shove the real lines into the tail; collapsed
    // accounting sees a few bytes of spinner + the log and never truncates.
    reset_capture();
    run_cmd(e, s, "i=1; while [ $i -le 4000 ]; do printf '\\342\\240\\231\\033[1G\\033[0K'; i=$((i+1)); done; "
                  "echo; i=1; while [ $i -le 20 ]; do echo real-line-$i; i=$((i+1)); done", "safe");
    if (memmem(g_out, g_out_len, "[truncated", 10)) {
        fprintf(stderr, "[spinner] truncated on redraw junk (head_len=%zu total=%zu)\n", s->ob.head_len, s->ob.total_len);
        return 1;
    }
    if (!memmem(g_out, g_out_len, "real-line-20", 12)) { fprintf(stderr, "[spinner] real log missing\n"); return 1; }
    if (s->ob.total_len > 2000) { fprintf(stderr, "[spinner] effective accounting too high: %zu\n", s->ob.total_len); return 1; }
    printf("[spinner] OK (%zu raw bytes streamed, %zu effective)\n", g_out_len, s->ob.total_len);

    // ── Spinner inside a flood: the tail is stored collapsed, so the real
    // trailing lines survive instead of being evicted by redraw frames ──
    reset_capture();
    run_cmd(e, s, "i=1; while [ $i -le 3000 ]; do echo flood-$i; i=$((i+1)); done; "
                  "i=1; while [ $i -le 3000 ]; do printf 'step %d\\r' $i; i=$((i+1)); done; echo; "
                  "i=1; while [ $i -le 5 ]; do echo tail-line-$i; i=$((i+1)); done", "safe");
    if (!memmem(g_out, g_out_len, "[truncated", 10)) { fprintf(stderr, "[cr-tail] expected truncation\n"); return 1; }
    if (!memmem(g_out, g_out_len, "flood-2500\n", 11)) { fprintf(stderr, "[cr-tail] collapsed tail lost pre-spinner lines\n"); return 1; }
    if (!memmem(g_out, g_out_len, "step 3000\ntail-line-1", 20)) { fprintf(stderr, "[cr-tail] spinner not collapsed to final frame; last 300 bytes:\n%.*s\n", 300, g_out + (g_out_len > 300 ? g_out_len - 300 : 0)); return 1; }
    printf("[cr-tail] OK (tail holds collapsed lines)\n");

    bridge_pty_close(&s->pty);
    free(e->sessions);
    free(e);
    printf("\nall tests passed\n");
    return 0;
}
