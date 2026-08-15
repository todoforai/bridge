// Per-RUN env exported into the PTY: TODOFORAI_MESSAGE_ID / TODOFORAI_BLOCK_ID
// (chat routing for tfa-* sub-todo linking) and the session-scoped ids next to
// them.
//
// The point of the suite is the LIFETIME difference. todoId/groupTag are
// session state ("absent ⇒ keep whatever the session had"), but the chat
// message/block pair identifies ONE chat block — a later step on the same
// persistent PTY must never inherit it, or a tfa-* child would link its
// sub-todo to the wrong block. So the wrapper always exports-or-unsets them.
//
// Includes main.c directly (renaming its main + stubbing the Noise send) so the
// real handle_command → wrapper → PTY path is exercised end to end: the RUN is
// fed as actual JSON and the assertions read the env back out of the shell.
// Build+run: make test-runenv

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_out[256 * 1024];   // decoded OUTPUT payload of the current run
static size_t g_out_len;
static int  g_done;              // step_done seen
static char g_error[256];        // last error frame's code

static int test_capture(const char *json, size_t len);

#define noise_ws_send bridge_test_noise_send
#define main bridge_main_unused
#include "../main.c"
#undef main

int bridge_test_noise_send(noise_ws_t *n, ws_t *w, const uint8_t *pt, size_t pt_len) {
    (void)n; (void)w;
    return test_capture((const char *)pt, pt_len);
}

static int test_capture(const char *json, size_t len) {
    const char *type = NULL; size_t type_len = 0;
    if (!json_get_str(json, len, "type", &type, &type_len)) return 0;
    if (type_len == 9 && memcmp(type, "step_done", 9) == 0) { g_done = 1; return 0; }
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

// Feed one RUN frame through handle_command and pump the loop to step_done.
// `extra` is raw JSON spliced into the frame (the per-RUN id fields under test).
// The command echoes the env vars back so the assertions can read them.
static void run_step(edge_t *e, const char *session_id, const char *extra) {
    static const char *CMD =
        "echo \"T=[$TODOFORAI_TODO_ID] G=[$TODOFORAI_GROUP_ID] A=[$AGENT_BROWSER_SESSION]"
        " M=[$TODOFORAI_MESSAGE_ID] B=[$TODOFORAI_BLOCK_ID] F=[$TODOFORAI_FRONTEND_ID]\"";
    char cmd_b64[512];
    size_t bn = b64_encode((const uint8_t *)CMD, strlen(CMD), cmd_b64, sizeof cmd_b64);
    assert(bn > 0);
    cmd_b64[bn] = '\0';

    char frame[1024];
    int fn = snprintf(frame, sizeof frame,
        "{\"type\":\"run\",\"sessionId\":\"%s\",\"blockId\":\"rpc-1\",\"cmdB64\":\"%s\","
        "\"timeoutMs\":10000,\"output\":\"raw\"%s%s}",
        session_id, cmd_b64, extra[0] ? "," : "", extra);
    assert(fn > 0 && (size_t)fn < sizeof frame);

    g_out_len = 0; g_done = 0; g_error[0] = '\0';
    assert(handle_command(e, frame, (size_t)fn) == 0);

    session_t *s = find_session(e, session_id, strlen(session_id));
    assert(s);
    for (int i = 0; i < 1000 && !g_done && s->state == SESS_RUNNING; i++) {
        struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
        poll(&pfd, 1, 20);
        service_sessions(e);
    }
    g_out[g_out_len] = '\0';
    // A rejected RUN reports an error instead of running; anything else must
    // reach step_done, or partial output could make a stuck step look fine.
    assert(g_done || g_error[0]);
}

static int g_fails;

static void expect(const char *label, const char *needle) {
    if (memmem(g_out, g_out_len, needle, strlen(needle))) return;
    fprintf(stderr, "FAIL %s: want %s\n  got: %.*s\n", label, needle, (int)g_out_len, g_out);
    g_fails++;
}

static void ok(const char *label) { printf("ok   %s\n", label); }

int main(void) {
    g_max_sessions = 4;
    edge_t *e = calloc(1, sizeof *e);
    assert(e);
    e->sessions = calloc((size_t)g_max_sessions, sizeof *e->sessions);
    assert(e->sessions);
    e->noise.handshake_done = 1;   // send_json's gate; the send itself is shimmed

    // A persistent session, so every RUN below reuses one live shell — the
    // only way a stale export from a previous step can be observed.
    const char *SID = "00000000-0000-4000-8000-000000000000";
    session_t *s = &e->sessions[0];
    assert(bridge_pty_spawn(&s->pty, "/bin/sh", NULL, /*no_echo=*/1) == 0);
    s->active = 1;
    s->state = SESS_IDLE;
    s->one_shot = 0;
    snprintf(s->session_id, sizeof s->session_id, "%s", SID);

    // ── The pair is exported when sent ──
    run_step(e, SID, "\"todoId\":\"todo-1\",\"groupTag\":\"grp-1\","
                "\"chatMessageId\":\"msg-1\",\"chatBlockId\":\"blk-1\"");
    expect("pair exported", "M=[msg-1] B=[blk-1]");
    expect("session ids exported", "T=[todo-1] G=[grp-1]");
    expect("todoId aliases the browser session", "A=[todo-1]");
    ok("chat ids + session ids are exported into the PTY");

    // ── Omitted on the next step of the SAME shell ⇒ unset, not inherited ──
    // This is the bug the pair exists to avoid: a tfa-* child in step 2 would
    // otherwise link its sub-todo to step 1's block.
    run_step(e, SID, "\"todoId\":\"todo-1\"");
    expect("chat ids cleared", "M=[] B=[]");
    expect("session ids survive", "T=[todo-1] G=[grp-1]");
    ok("omitted chat ids are unset, session ids keep their value");

    // ── A half-set pair links nothing, so it must not half-export ──
    run_step(e, SID, "\"chatMessageId\":\"msg-2\"");
    expect("half pair dropped", "M=[] B=[]");
    ok("a message id without a block id is dropped, not half-exported");

    run_step(e, SID, "\"chatMessageId\":\"msg-3\",\"chatBlockId\":\"blk-3\"");
    expect("pair re-exported", "M=[msg-3] B=[blk-3]");
    run_step(e, SID, "\"chatBlockId\":\"blk-4\"");
    expect("stale counterpart not reused", "M=[] B=[]");
    ok("a block id can't pair with the previous step's message id");

    // ── Charset validation (ids interpolate raw into the wrapper) ──
    run_step(e, SID, "\"chatMessageId\":\"m;rm -rf /\",\"chatBlockId\":\"blk-5\"");
    if (strcmp(g_error, "INVALID_MESSAGE_ID") != 0) {
        fprintf(stderr, "FAIL injection: want INVALID_MESSAGE_ID, got '%s'\n", g_error);
        g_fails++;
    }
    run_step(e, SID, "\"chatMessageId\":\"msg-6\",\"chatBlockId\":\"b$(id)\"");
    if (strcmp(g_error, "INVALID_CHAT_BLOCK_ID") != 0) {
        fprintf(stderr, "FAIL injection: want INVALID_CHAT_BLOCK_ID, got '%s'\n", g_error);
        g_fails++;
    }
    ok("shell-unsafe chat ids are rejected before reaching the wrapper");

    // ── A rejected RUN must commit nothing ──
    // Ids are validated into locals before any is written to the session, so
    // a valid field sitting next to an invalid one in the same frame can't
    // sneak through on the error path.
    run_step(e, SID, "\"todoId\":\"todo-9\",\"groupTag\":\"grp-9\",\"chatBlockId\":\"b;id\"");
    if (strcmp(g_error, "INVALID_CHAT_BLOCK_ID") != 0) {
        fprintf(stderr, "FAIL reject: want INVALID_CHAT_BLOCK_ID, got '%s'\n", g_error);
        g_fails++;
    }
    run_step(e, SID, "");
    expect("session ids unchanged by rejected run", "T=[todo-1] G=[grp-1]");
    ok("a rejected RUN leaves session ids untouched");

    // ── A recycled slot must not leak the previous occupant's ids ──
    run_step(e, SID, "\"chatMessageId\":\"msg-7\",\"chatBlockId\":\"blk-7\"");
    expect("pair exported before recycle", "M=[msg-7] B=[blk-7]");
    bridge_pty_close(&s->pty);
    s->active = 0;
    // Fresh one-shot RUN with no sessionId → handle_command claims this slot.
    // Only the chat pair is asserted: the wrapper never exports a cleared
    // todoId, so `$TODOFORAI_TODO_ID` would show whatever the bridge process
    // itself inherited — which is the developer's shell under `make test`.
    const char *CMD = "echo \"M=[$TODOFORAI_MESSAGE_ID] B=[$TODOFORAI_BLOCK_ID]\"";
    char cmd_b64[512];
    size_t bn = b64_encode((const uint8_t *)CMD, strlen(CMD), cmd_b64, sizeof cmd_b64);
    cmd_b64[bn] = '\0';
    char frame[1024];
    int fn = snprintf(frame, sizeof frame,
        "{\"type\":\"run\",\"blockId\":\"rpc-2\",\"cmdB64\":\"%s\",\"timeoutMs\":10000,\"output\":\"raw\"}",
        cmd_b64);
    g_out_len = 0; g_done = 0; g_error[0] = '\0';
    assert(handle_command(e, frame, (size_t)fn) == 0);
    for (int i = 0; i < 1000 && !g_done; i++) {
        struct pollfd pfd = { .fd = bridge_pty_pollfd(&s->pty), .events = POLLIN };
        poll(&pfd, 1, 20);
        service_sessions(e);
    }
    g_out[g_out_len] = '\0';
    assert(g_done && !g_error[0]);
    expect("recycled slot is clean", "M=[] B=[]");
    ok("a recycled session slot starts with no chat ids");

    if (g_fails) { fprintf(stderr, "\n%d check(s) failed\n", g_fails); return 1; }
    printf("\nall run-env tests passed\n");
    return 0;
}
