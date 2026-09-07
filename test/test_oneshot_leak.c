// One-shot PTY lifecycle: every RUN without a sessionId must release its
// shell at STEP_DONE — including runs that were parked (STEP_AWAITING_INPUT)
// in between. A parked one-shot that finishes has nobody left to address it
// (the backend drops the pid at STEP_DONE), so keeping it alive is a leak.
//
// Seen in production on Windows: bridgeFileChanges' snapshot scripts hit
// their 20s deadline, the deadline path parks them (ConPTY has no
// blocked-on-stdin probe), and park_step used to flip one_shot=0 → one idle
// bash pair per slow RUN, ~260 after a day, until the box was CPU-starved
// and every RUN returned empty output. Builds like test_initdrain (includes
// main.c, stubs the Noise send). Run: make test-oneshot-leak

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <assert.h>
#include <poll.h>
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

static int g_step_done, g_awaiting, g_errors;
static char g_last_error[256];

int bridge_test_noise_send(noise_ws_t *n, ws_t *w, const uint8_t *pt, size_t pt_len) {
    (void)n; (void)w;
    return test_capture((const char *)pt, pt_len);
}

static int test_capture(const char *json, size_t len) {
    const char *type = NULL; size_t type_len = 0;
    if (!json_get_str(json, len, "type", &type, &type_len)) return 0;
    if (type_len == 9  && !memcmp(type, "step_done", 9)) g_step_done++;
    if (type_len == 19 && !memcmp(type, "step_awaiting_input", 19)) g_awaiting++;
    if (type_len == 5  && !memcmp(type, "error", 5)) {
        g_errors++;
        const char *code = NULL; size_t cl = 0;
        json_get_str(json, len, "code", &code, &cl);
        snprintf(g_last_error, sizeof g_last_error, "%.*s", (int)cl, code ? code : "");
    }
    return 0;
}

static int active_sessions(edge_t *e) {
    int n = 0;
    for (int i = 0; i < g_max_sessions; i++) n += e->sessions[i].active != 0;
    return n;
}

static int child_count(void) {
    char cmd[128];
    snprintf(cmd, sizeof cmd, "pgrep -P %d | wc -l", (int)getpid());
    FILE *f = popen(cmd, "r");
    assert(f);
    int n = -1;
    if (fscanf(f, "%d", &n) != 1) n = -1;
    pclose(f);
    return n;
}

// Feed a RUN frame (one-shot: no sessionId). cmd is base64'd here; timeoutMs
// optional (0 = none).
static void send_run(edge_t *e, const char *cmd, long timeout_ms) {
    static int seq = 0;
    char b64[4096];
    size_t bl = b64_encode(cmd, strlen(cmd), b64, sizeof b64);
    b64[bl] = '\0';
    char frame[8192];
    char tmo[48] = "";
    if (timeout_ms) snprintf(tmo, sizeof tmo, ",\"timeoutMs\":%ld", timeout_ms);
    int n = snprintf(frame, sizeof frame,
        "{\"type\":\"run\",\"blockId\":\"run_%d\",\"cmdB64\":\"%s\",\"cwd\":\"/tmp\"%s}",
        ++seq, b64, tmo);
    assert(n > 0 && (size_t)n < sizeof frame);
    handle_command(e, frame, (size_t)n);
}

// Pump the loop until `pred` holds or `ms` elapses.
static int pump_until(edge_t *e, int (*pred)(edge_t *), int ms) {
    int64_t end = monotonic_ms() + ms;
    while (monotonic_ms() < end) {
        if (pred(e)) return 1;
        struct pollfd pfd = { .fd = -1 };
        poll(&pfd, 0, 10);
        service_sessions(e);
    }
    return pred(e);
}
static int no_active(edge_t *e) { return active_sessions(e) == 0; }
static int parked_any(edge_t *e) {
    for (int i = 0; i < g_max_sessions; i++)
        if (e->sessions[i].active && e->sessions[i].parked) return 1;
    return 0;
}

static edge_t *mk_edge(void) {
    edge_t *e = calloc(1, sizeof *e);
    assert(e);
    e->sessions = calloc((size_t)g_max_sessions, sizeof *e->sessions);
    assert(e->sessions);
    e->noise.handshake_done = 1;
    snprintf(e->api_url, sizeof e->api_url, "http://test");
    return e;
}

static session_t *find_parked(edge_t *e) {
    for (int i = 0; i < g_max_sessions; i++)
        if (e->sessions[i].active && e->sessions[i].parked) return &e->sessions[i];
    return NULL;
}

int main(void) {
    g_max_sessions = 8;
    int fails = 0;
    int base_children = child_count();
    fprintf(stderr, "baseline children: %d\n", base_children);

    // 1. Plain one-shots: N sequential RUNs, every shell reaped at STEP_DONE.
    {
        edge_t *e = mk_edge();
        const int N = 40;
        for (int i = 0; i < N; i++) {
            send_run(e, "echo hi", 0);
            if (!pump_until(e, no_active, 5000)) { fprintf(stderr, "[plain] run %d never finished\n", i); fails++; break; }
        }
        int kids = child_count();
        if (g_step_done != N || kids != base_children) {
            fprintf(stderr, "[plain] FAIL: step_done=%d/%d children=%d (base %d)\n", g_step_done, N, kids, base_children);
            fails++;
        } else fprintf(stderr, "[plain] OK: %d one-shots, children flat at %d\n", N, kids);
        free(e->sessions); free(e);
    }

    // 2. Parked one-shots: park each run mid-flight (the `detach` frame takes
    //    the exact path the Windows deadline and the POSIX probe take), let
    //    it finish, and require the shell to be gone at STEP_DONE.
    {
        edge_t *e = mk_edge();
        g_step_done = 0; g_awaiting = 0;
        const int N = 20;
        for (int i = 0; i < N; i++) {
            send_run(e, "sleep 0.3; echo done", 0);
            // Find the running session and detach it.
            session_t *s = NULL;
            for (int j = 0; j < g_max_sessions; j++)
                if (e->sessions[j].active && e->sessions[j].state == SESS_RUNNING) { s = &e->sessions[j]; break; }
            if (!s) { fprintf(stderr, "[parked] run %d: no running session\n", i); fails++; break; }
            char det[256];
            int dn = snprintf(det, sizeof det, "{\"type\":\"detach\",\"sessionId\":\"%s\"}", s->session_id);
            handle_command(e, det, (size_t)dn);
            if (!pump_until(e, parked_any, 1000) && !s->parked) {
                fprintf(stderr, "[parked] run %d: detach did not park\n", i); fails++; break;
            }
            if (!pump_until(e, no_active, 5000)) {
                session_t *p = find_parked(e);
                fprintf(stderr, "[parked] FAIL: run %d — session %s still active after STEP_DONE (one_shot=%d)\n",
                        i, p ? p->session_id : "?", p ? p->one_shot : -1);
                fails++; break;
            }
        }
        int kids = child_count();
        if (!fails && (g_awaiting != N || g_step_done != N || kids != base_children)) {
            fprintf(stderr, "[parked] FAIL: awaiting=%d step_done=%d/%d children=%d (base %d)\n",
                    g_awaiting, g_step_done, N, kids, base_children);
            fails++;
        } else if (!fails) fprintf(stderr, "[parked] OK: %d parked one-shots, children flat at %d\n", N, kids);
        free(e->sessions); free(e);
    }

    // 2b. Resume window: a parked one-shot blocked on stdin must stay alive
    //     (agent resumes by minted sessionId), then be reaped only at STEP_DONE.
    {
        edge_t *e = mk_edge();
        g_step_done = 0; g_awaiting = 0;
        send_run(e, "read -r x; echo got:$x", 0);
        session_t *s = NULL;
        for (int j = 0; j < g_max_sessions; j++)
            if (e->sessions[j].active && e->sessions[j].state == SESS_RUNNING) { s = &e->sessions[j]; break; }
        assert(s);
        char sid[64]; snprintf(sid, sizeof sid, "%s", s->session_id);
        char det[256];
        int dn = snprintf(det, sizeof det, "{\"type\":\"detach\",\"sessionId\":\"%s\"}", sid);
        handle_command(e, det, (size_t)dn);
        pump_until(e, parked_any, 1000);
        // Still parked + alive 300ms later: STEP_AWAITING_INPUT must not tear down.
        pump_until(e, no_active, 300);
        if (g_awaiting != 1 || g_step_done != 0 || !find_parked(e) || child_count() != base_children + 1) {
            fprintf(stderr, "[resume] FAIL: closed at park (awaiting=%d done=%d children=%d)\n",
                    g_awaiting, g_step_done, child_count());
            fails++;
        } else {
            char inp[256];
            int in = snprintf(inp, sizeof inp, "{\"type\":\"input\",\"sessionId\":\"%s\",\"data\":\"aGkK\"}", sid);  // "hi\n"
            handle_command(e, inp, (size_t)in);
            if (!pump_until(e, no_active, 5000) || g_step_done != 1 || child_count() != base_children) {
                fprintf(stderr, "[resume] FAIL: after input done=%d active=%d children=%d\n",
                        g_step_done, active_sessions(e), child_count());
                fails++;
            } else fprintf(stderr, "[resume] OK: parked one-shot resumed by sessionId, reaped at STEP_DONE\n");
        }
        for (int i = 0; i < g_max_sessions; i++)
            if (e->sessions[i].active) { bridge_pty_signal(&e->sessions[i].pty, 9); bridge_pty_close(&e->sessions[i].pty); e->sessions[i].active = 0; }
        free(e->sessions); free(e);
    }

    // 3. Full table must answer with an explicit ERROR frame, never silence.
    {
        edge_t *e = mk_edge();
        g_errors = 0;
        for (int i = 0; i < g_max_sessions; i++) send_run(e, "sleep 30", 0);
        // Every slot is SESS_RUNNING → no LRU victim.
        int active_before = active_sessions(e);
        send_run(e, "echo overflow", 0);
        if (g_errors != 1 || strcmp(g_last_error, "MAX_SESSIONS") != 0 || active_sessions(e) != active_before) {
            fprintf(stderr, "[full] FAIL: errors=%d last=%s active=%d/%d\n",
                    g_errors, g_last_error, active_sessions(e), active_before);
            fails++;
        } else fprintf(stderr, "[full] OK: MAX_SESSIONS error on slot %d\n", g_max_sessions + 1);
        for (int i = 0; i < g_max_sessions; i++)
            if (e->sessions[i].active) { bridge_pty_signal(&e->sessions[i].pty, 9); bridge_pty_close(&e->sessions[i].pty); e->sessions[i].active = 0; }
        free(e->sessions); free(e);
    }

    if (fails) fprintf(stderr, "\n%d test(s) failed\n", fails);
    else       fprintf(stderr, "\nall one-shot leak tests passed\n");
    return fails ? 1 : 0;
}
