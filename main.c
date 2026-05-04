// TODOforAI Bridge — C runtime. TCP → WebSocket → Noise_NX → PTY relay.
//
// Protocol (inside Noise transport):
//   First encrypted msg (edge→server):
//     {"type":"auth","deviceId":"dev_...","secret":"..."}
//   Then v2 control messages (JSON). The bridge knows ONE identifier:
//   `sessionId` (UUID it mints when a PTY is spawned via RUN with
//   sessionId="new"). It has no notion of TODOs — that mapping lives in the
//   backend. `blockId` rides on RUN frames as an RPC correlation key.
//     → {"type":"identity","data":{...}}
//     ← {"type":"run","sessionId":"new"|"uuid","blockId":"...","cmdB64":"...","cwd":"...","timeoutMs":N}
//     → {"type":"run_started","sessionId":"uuid","blockId":"...","created":bool}
//     → {"type":"output","sessionId":"uuid","blockId":"...","data":"base64"}
//     → {"type":"step_paused","sessionId":"uuid","blockId":"...","passwordPrompt":bool}
//     → {"type":"step_done","sessionId":"uuid","blockId":"...","exitCode":N|null,"alive":bool,"timedOut":bool}
//     ← {"type":"input","sessionId":"uuid","data":"base64","requestId":"..."}   // resumes paused RUN
//     ← {"type":"signal","sessionId":"uuid","signal":"SIGINT|SIGTERM|SIGKILL","requestId":"..."}
//     → {"type":"ack","requestId":"..."}                            // success reply for input/signal
//     ← {"type":"close","sessionId":"uuid","force":bool}
//     → {"type":"exit","sessionId":"uuid","blockId":"...","code":N}
//     ↔ {"type":"error","sessionId":"uuid","blockId":"...","code":"ERR","message":"..."}

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE          // memmem (Linux glibc); harmless on musl/Darwin

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "args.h"      // ketopt + cli_usage helpers
#include "identity.h"  // BRIDGE_VERSION
#include "mongoose.h"
#include "noise.h"     // noise_random
#include "noise_ws.h"
#include "pty.h"
#include "subcmd.h"
#include "tools.h"
#include "update.h"
#include "login.h"

// Custom RNG for mongoose (MG_ENABLE_CUSTOM_RANDOM=1) — reuse our Noise RNG so
// we don't pull mongoose's per-arch random implementations into the binary.
bool mg_random(void *buf, size_t len) {
    return noise_random((uint8_t *)buf, len) == 0;
}

// ── Defaults ────────────────────────────────────────────────────────────────

#define DEFAULT_HOST         "api.todofor.ai"
// Plain HTTP port — bridge has no TLS client; Noise provides end-to-end crypto.
#define DEFAULT_PORT         80
#define DEFAULT_PATH         "/ws/v2/bridge"
#define DEFAULT_SHELL        "/bin/sh"
#define BUF_SIZE             4096
#define MAX_SESSIONS         16
#define SESSION_ID_LEN       36
#define BLOCK_ID_CAP         64
#define MAX_MSG              (64 * 1024)

// Server's Noise static public key (X25519, 32 bytes hex = 64 chars).
// Overridable via EDGE_SERVER_PUBKEY env or --server-pubkey flag.
// Same key used by sandbox-manager / browser-manager CLIs on port 4100 —
// backend uses NOISE_LOCAL_PRIVATE_KEY for both the TCP RPC server and the
// bridge WS handler.
#define DEFAULT_SERVER_PUBKEY_HEX \
    "7215aaeea295f0c1234d3fd8aa42da6fb93da010cc8dd2d2f6c1d43435c8fe2f"

// ── Session ─────────────────────────────────────────────────────────────────

// Per-step sentinel envelope (bridge owns this; backend never sees raw bytes).
//   Wrapper:    { <user-cmd>\n}; __RC=$?; printf '\n<sentinel>:%d\n' "$__RC"\n
//   Sentinel:   __BRIDGE_STEP_<32 hex>__   → 16 + 32 + 2 = 50 chars; pad to 64.
#define SENTINEL_CAP   64
// Upper bound: previous read may have left up to (sentinel_len - 1) bytes in
// the tail; the next read appends ≤ BUF_SIZE bytes. SENTINEL_CAP overshoots
// `sentinel_len - 1` and rounds the buffer to a power of two.
#define TAIL_CAP       (BUF_SIZE + SENTINEL_CAP)

typedef enum { SESS_IDLE = 0, SESS_RUNNING } sess_state_t;

typedef struct {
    int active;
    // PTY identity. UUID v4 minted by the bridge on RUN with sessionId="new".
    // Authoritative routing key; the bridge looks up sessions by this.
    char session_id[SESSION_ID_LEN + 1];
    bridge_pty_t pty;

    // Opaque echo label set from RunMessage.todoId. Bridge never interprets
    // it — just stashes it on the session and echoes it on every related
    // frame so the backend's OUTPUT/EXIT/ERROR routing is self-describing.
    char todo_id[BLOCK_ID_CAP + 1];
    size_t todo_id_len;

    // RUN state machine ----------------------------------------------------
    // PTY echo is disabled at spawn, so the wrapper command line never
    // appears in OUTPUT and the sentinel scan is unambiguous.
    sess_state_t state;
    char sentinel[SENTINEL_CAP];
    size_t sentinel_len;
    // Per-step routing (echoed in OUTPUT/STEP_DONE while running).
    char run_block_id[BLOCK_ID_CAP + 1];
    size_t run_block_id_len;
    int64_t deadline_ms;                 // 0 = no deadline
    // Rolling tail buffer: holds the trailing (sentinel_len) bytes that
    // could be the start of a sentinel split across read() chunks.
    uint8_t tail_buf[TAIL_CAP];
    size_t  tail_len;
    // Idle-GC: monotonic ms of last activity (spawn / INPUT / OUTPUT / STEP_DONE).
    // Sessions in SESS_IDLE that go quiet for IDLE_TIMEOUT_MS are SIGKILL'd to
    // free the slot. SESS_RUNNING sessions are exempt — they have deadline_ms.
    int64_t last_active_ms;
    // Pause detection (RUN only): poll the wchan probe every PAUSE_POLL_MS
    // and emit STEP_PAUSED once `blocked` is observed PAUSE_CONFIRM_TICKS
    // times in a row. Any non-blocked tick resets the counter, so resumption
    // (input arrived → process leaves n_tty_read) is detected implicitly.
    int64_t last_pause_poll_ms;
    int     pause_consec_ticks;
} session_t;

// Pause poll cadence + confirmation. 2 ticks at 250 ms ⇒ ~250-500 ms latency
// to detect a real prompt; FP rate ~1-2% (vs. ~30-60% for output-quiescence).
#define PAUSE_POLL_MS        250
#define PAUSE_CONFIRM_TICKS  2

// 30 min — see Phase 3 step 6. Picked to outlive a typical agent step but
// reclaim slots when an agent crashes / forgets to CLOSE.
#define IDLE_TIMEOUT_MS (30 * 60 * 1000)

typedef struct {
    struct mg_mgr mgr;
    struct mg_connection *ws;
    noise_ws_t noise;
    const char *device_id;
    const char *device_secret;
    int done;
    int rc;
    // Auth → identity sequencing. Backend's pre-auth handler awaits
    // validateDevice() asynchronously; if both frames land in one TCP segment
    // (mongoose coalesces them), the second hits the handler with
    // authenticated=false and is rejected as "expected auth". Defer identity
    // until the auth round-trip has had time to settle on the backend.
    int identity_sent;
    int64_t auth_sent_ms;

    session_t sessions[MAX_SESSIONS];
    uint8_t  pty_buf[BUF_SIZE];
    char     b64_buf[BUF_SIZE * 2];
    uint8_t  msg_buf[MAX_MSG];
} edge_t;

// ── Helpers ─────────────────────────────────────────────────────────────────

static int64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void hex_encode(char *out, const uint8_t *in, size_t n) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i*2]     = H[in[i] >> 4];
        out[i*2 + 1] = H[in[i] & 0xF];
    }
    out[n*2] = '\0';
}

// Build a UUID v4 string into out[37].
static void gen_uuid_v4(char out[37]) {
    uint8_t b[16];
    noise_random(b, 16);
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    static const char H[] = "0123456789abcdef";
    int o = 0;
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[o++] = '-';
        out[o++] = H[b[i] >> 4];
        out[o++] = H[b[i] & 0xF];
    }
    out[o] = '\0';
}

// Generate `__BRIDGE_STEP_<32 hex>__` into out (≤ SENTINEL_CAP). Returns length.
static size_t gen_sentinel(char *out, size_t cap) {
    static const char prefix[] = "__BRIDGE_STEP_";
    static const char suffix[] = "__";
    uint8_t rnd[16];
    noise_random(rnd, sizeof(rnd));
    char hex[33];
    hex_encode(hex, rnd, sizeof(rnd));
    int n = snprintf(out, cap, "%s%s%s", prefix, hex, suffix);
    return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}


static int json_path(char *out, size_t cap, const char *key) {
    int n = snprintf(out, cap, "$.%s", key);
    return n > 0 && (size_t)n < cap;
}

static int json_str(const char *data, size_t data_len,
                    const char *key, const char **out, size_t *out_len) {
    char path[64];
    if (!json_path(path, sizeof(path), key)) return 0;
    struct mg_str tok = mg_json_get_tok(mg_str_n(data, data_len), path);
    if (!tok.buf || tok.len < 2 || tok.buf[0] != '"') return 0;
    *out = tok.buf + 1;
    *out_len = tok.len - 2;
    return 1;
}

static int json_str_decoded(const char *data, size_t data_len,
                            const char *key, char *out, size_t out_cap,
                            size_t *out_len) {
    char path[64];
    if (!json_path(path, sizeof(path), key)) return 0;
    size_t n = mg_json_unescape(mg_str_n(data, data_len), path, out, out_cap);
    if (n == 0) return 0;
    *out_len = n;
    return 1;
}

static int json_bool(const char *data, size_t data_len,
                     const char *key, int *out) {
    char path[64];
    bool b = false;
    if (!json_path(path, sizeof(path), key)) return 0;
    if (!mg_json_get_bool(mg_str_n(data, data_len), path, &b)) return 0;
    *out = b ? 1 : 0;
    return 1;
}

static int json_int(const char *data, size_t data_len,
                    const char *key, long *out) {
    char path[64];
    double d = 0;
    if (!json_path(path, sizeof(path), key)) return 0;
    if (!mg_json_get_num(mg_str_n(data, data_len), path, &d)) return 0;
    *out = (long)d;
    return 1;
}

static int is_valid_uuid(const char *s, size_t len) {
    if (len != 36) return 0;
    for (size_t i = 0; i < 36; i++) {
        char c = s[i];
        int is_dash = (i == 8 || i == 13 || i == 18 || i == 23);
        if (is_dash) { if (c != '-') return 0; }
        else if (!isxdigit((unsigned char)c)) return 0;
    }
    return 1;
}

// Restrict free-form IDs (blockId) to a charset that's both shell- and
// JSON-safe so we can interpolate them raw with %s. Backend chooses these
// IDs, so the constraint is enforceable upstream.
static int is_valid_id(const char *s, size_t len) {
    if (len == 0 || len > BLOCK_ID_CAP) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
        if (!ok) return 0;
    }
    return 1;
}

static session_t *find_session(edge_t *e, const char *sid, size_t sid_len) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &e->sessions[i];
        if (s->active && strlen(s->session_id) == sid_len &&
            memcmp(s->session_id, sid, sid_len) == 0) {
            return s;
        }
    }
    return NULL;
}

static session_t *free_slot(edge_t *e) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!e->sessions[i].active) return &e->sessions[i];
    }
    return NULL;
}

static int send_json(edge_t *e, const char *s, size_t n) {
    if (!e->ws || !e->noise.handshake_done) return -1;
    return noise_ws_send(&e->noise, e->ws, (const uint8_t *)s, n);
}

#define MG_ESC_N(s, n) mg_print_esc, (int)(n), (char *)(s)

static int send_error(edge_t *e,
                      const char *sid, size_t sid_len,
                      const char *bid, size_t bid_len,
                      const char *code, const char *message) {
    char buf[1024];
    int n;
    if (sid && bid) {
        n = (int)mg_snprintf(buf, sizeof(buf),
            "{%m:%m,%m:%m,%m:%m,%m:%m,%m:%m}",
            MG_ESC("type"), MG_ESC("error"),
            MG_ESC("sessionId"), MG_ESC_N(sid, sid_len),
            MG_ESC("blockId"), MG_ESC_N(bid, bid_len),
            MG_ESC("code"), MG_ESC(code),
            MG_ESC("message"), MG_ESC(message));
    } else if (sid) {
        n = (int)mg_snprintf(buf, sizeof(buf),
            "{%m:%m,%m:%m,%m:%m,%m:%m}",
            MG_ESC("type"), MG_ESC("error"),
            MG_ESC("sessionId"), MG_ESC_N(sid, sid_len),
            MG_ESC("code"), MG_ESC(code),
            MG_ESC("message"), MG_ESC(message));
    } else {
        n = (int)mg_snprintf(buf, sizeof(buf),
            "{%m:%m,%m:%m,%m:%m}",
            MG_ESC("type"), MG_ESC("error"),
            MG_ESC("code"), MG_ESC(code),
            MG_ESC("message"), MG_ESC(message));
    }
    if (n > 0 && (size_t)n < sizeof(buf)) send_json(e, buf, (size_t)n);
    fprintf(stderr, "error %s: %s\n", code, message);
    return 0;
}

// Reply to an INPUT/SIGNAL request that failed. Same as send_error but
// also echoes `requestId` so the backend can settle the right pending call.
// `rid` is is_valid_id-validated upstream and safe to interpolate raw.
static int send_req_error(edge_t *e,
                          const char *sid, size_t sid_len,
                          const char *rid, size_t rid_len,
                          const char *code, const char *message) {
    char buf[1024];
    int n;
    if (sid) {
        n = (int)mg_snprintf(buf, sizeof(buf),
            "{%m:%m,%m:%m,%m:%m,%m:%m,%m:%m}",
            MG_ESC("type"), MG_ESC("error"),
            MG_ESC("sessionId"), MG_ESC_N(sid, sid_len),
            MG_ESC("requestId"), MG_ESC_N(rid, rid_len),
            MG_ESC("code"), MG_ESC(code),
            MG_ESC("message"), MG_ESC(message));
    } else {
        n = (int)mg_snprintf(buf, sizeof(buf),
            "{%m:%m,%m:%m,%m:%m,%m:%m}",
            MG_ESC("type"), MG_ESC("error"),
            MG_ESC("requestId"), MG_ESC_N(rid, rid_len),
            MG_ESC("code"), MG_ESC(code),
            MG_ESC("message"), MG_ESC(message));
    }
    if (n > 0 && (size_t)n < sizeof(buf)) send_json(e, buf, (size_t)n);
    fprintf(stderr, "error %s: %s\n", code, message);
    return 0;
}

static int send_ack(edge_t *e, const char *rid, size_t rid_len) {
    char buf[128];
    int n = (int)mg_snprintf(buf, sizeof(buf),
        "{%m:%m,%m:%m}",
        MG_ESC("type"), MG_ESC("ack"),
        MG_ESC("requestId"), MG_ESC_N(rid, rid_len));
    if (n > 0 && (size_t)n < sizeof(buf)) return send_json(e, buf, (size_t)n);
    return -1;
}

// Optional `,"todoId":"..."` fragment if the session has an echo label.
// `todo_id` charset is is_valid_id-validated, safe to interpolate raw.
#define TODO_FRAG_FMT "%s%s%s"
#define TODO_FRAG_ARGS(s) \
    (s)->todo_id_len > 0 ? ",\"todoId\":\"" : "", \
    (s)->todo_id_len > 0 ? (s)->todo_id      : "", \
    (s)->todo_id_len > 0 ? "\""              : ""

static void send_exit(edge_t *e, session_t *s, int code) {
    char buf[384];
    int n;
    if (s->run_block_id_len > 0) {
        n = (int)mg_snprintf(buf, sizeof(buf),
            "{%m:%m,%m:%m" TODO_FRAG_FMT ",%m:%m,%m:%d}",
            MG_ESC("type"), MG_ESC("exit"),
            MG_ESC("sessionId"), MG_ESC(s->session_id),
            TODO_FRAG_ARGS(s),
            MG_ESC("blockId"), MG_ESC(s->run_block_id),
            MG_ESC("code"), code);
    } else {
        n = (int)mg_snprintf(buf, sizeof(buf),
            "{%m:%m,%m:%m" TODO_FRAG_FMT ",%m:%d}",
            MG_ESC("type"), MG_ESC("exit"),
            MG_ESC("sessionId"), MG_ESC(s->session_id),
            TODO_FRAG_ARGS(s),
            MG_ESC("code"), code);
    }
    if (n > 0 && (size_t)n < sizeof(buf)) send_json(e, buf, (size_t)n);
    fprintf(stderr, "PTY exited: %s code=%d\n", s->session_id, code);
}

// Emit OUTPUT for `len` bytes of PTY stream. blockId is included only while
// a RUN is in flight (echoed from the RUN frame for backend correlation).
static void send_output_bytes(edge_t *e, session_t *s,
                              const uint8_t *data, size_t len) {
    if (len == 0) return;
    size_t bn = mg_base64_encode(data, len, e->b64_buf, sizeof(e->b64_buf));
    if (bn == 0) return;
    size_t cap = bn + 256;
    char *msg = malloc(cap);
    if (!msg) return;
    int mn;
    if (s->state == SESS_RUNNING && s->run_block_id_len > 0) {
        mn = (int)mg_snprintf(msg, cap,
            "{%m:%m,%m:%m" TODO_FRAG_FMT ",%m:%m,%m:%m}",
            MG_ESC("type"), MG_ESC("output"),
            MG_ESC("sessionId"), MG_ESC(s->session_id),
            TODO_FRAG_ARGS(s),
            MG_ESC("blockId"), MG_ESC(s->run_block_id),
            MG_ESC("data"), MG_ESC_N(e->b64_buf, bn));
    } else {
        mn = (int)mg_snprintf(msg, cap,
            "{%m:%m,%m:%m" TODO_FRAG_FMT ",%m:%m}",
            MG_ESC("type"), MG_ESC("output"),
            MG_ESC("sessionId"), MG_ESC(s->session_id),
            TODO_FRAG_ARGS(s),
            MG_ESC("data"), MG_ESC_N(e->b64_buf, bn));
    }
    if (mn > 0 && (size_t)mn < cap) send_json(e, msg, (size_t)mn);
    free(msg);
}

static void send_run_started(edge_t *e, session_t *s, int created) {
    char buf[384];
    int n = (int)mg_snprintf(buf, sizeof(buf),
        "{%m:%m,%m:%m" TODO_FRAG_FMT ",%m:%m,%m:%s}",
        MG_ESC("type"), MG_ESC("run_started"),
        MG_ESC("sessionId"), MG_ESC(s->session_id),
        TODO_FRAG_ARGS(s),
        MG_ESC("blockId"), MG_ESC(s->run_block_id),
        MG_ESC("created"), created ? "true" : "false");
    if (n > 0 && (size_t)n < sizeof(buf)) send_json(e, buf, (size_t)n);
}

// exit_code < 0 ⇒ emit `null`. alive=false means shell died during the step.
static void send_step_done(edge_t *e, session_t *s, int has_code, int exit_code,
                           int alive, int timed_out) {
    char buf[512];
    char rc[24];
    if (has_code) mg_snprintf(rc, sizeof(rc), "%d", exit_code);
    else          mg_snprintf(rc, sizeof(rc), "null");
    int n = (int)mg_snprintf(buf, sizeof(buf),
        "{%m:%m,%m:%m" TODO_FRAG_FMT ",%m:%m,%m:%s,%m:%s,%m:%s}",
        MG_ESC("type"), MG_ESC("step_done"),
        MG_ESC("sessionId"), MG_ESC(s->session_id),
        TODO_FRAG_ARGS(s),
        MG_ESC("blockId"), MG_ESC(s->run_block_id),
        MG_ESC("exitCode"), rc,
        MG_ESC("alive"), alive ? "true" : "false",
        MG_ESC("timedOut"), timed_out ? "true" : "false");
    if (n > 0 && (size_t)n < sizeof(buf)) send_json(e, buf, (size_t)n);
}

// Bridge → server: "command is blocked waiting for stdin". The PTY stays
// alive and the RUN stays in flight; backend resolves the pending RUN promise
// with `paused:true` so the agent gets the prompt text and can resume by
// sending INPUT on the same sessionId.
// `passwordPrompt` is true when the slave has ECHO disabled (sudo/getpass/ssh).
static void send_step_paused(edge_t *e, session_t *s, int password_prompt) {
    char buf[512];
    int n = (int)mg_snprintf(buf, sizeof(buf),
        "{%m:%m,%m:%m" TODO_FRAG_FMT ",%m:%m,%m:%s}",
        MG_ESC("type"), MG_ESC("step_paused"),
        MG_ESC("sessionId"), MG_ESC(s->session_id),
        TODO_FRAG_ARGS(s),
        MG_ESC("blockId"), MG_ESC(s->run_block_id),
        MG_ESC("passwordPrompt"), password_prompt ? "true" : "false");
    if (n > 0 && (size_t)n < sizeof(buf)) send_json(e, buf, (size_t)n);
}

// Reset per-step state. Subsequent PTY bytes (e.g. trailing async output)
// emit OUTPUT without a blockId — the backend routes them to the session.
static void run_finish(session_t *s) {
    s->state = SESS_IDLE;
    s->tail_len = 0;
    s->deadline_ms = 0;
    s->run_block_id_len = 0;
    s->run_block_id[0] = '\0';
    s->sentinel_len = 0;
    s->pause_consec_ticks = 0;
    // Idle-GC: command just finished; restart the idle timer from now.
    s->last_active_ms = monotonic_ms();
}

// Search tail_buf for sentinel start (returns offset, or -1 if absent).
static ssize_t find_sentinel(const session_t *s) {
    if (s->tail_len < s->sentinel_len) return -1;
    void *m = memmem(s->tail_buf, s->tail_len, s->sentinel, s->sentinel_len);
    return m ? (ssize_t)((uint8_t *)m - s->tail_buf) : -1;
}

// Append `data[len]` into the tail buffer. By construction (see TAIL_CAP),
// the buffer always has room for one full PTY read plus the held-back tail.
static void tail_append(session_t *s, const uint8_t *data, size_t len) {
    if (len > TAIL_CAP - s->tail_len) len = TAIL_CAP - s->tail_len;
    memcpy(s->tail_buf + s->tail_len, data, len);
    s->tail_len += len;
}

static void forward_pty_output(edge_t *e, session_t *s) {
    long n = bridge_pty_read(&s->pty, e->pty_buf, sizeof(e->pty_buf));
    if (n <= 0) return;
    s->last_active_ms = monotonic_ms();

    if (s->state != SESS_RUNNING) {
        send_output_bytes(e, s, e->pty_buf, (size_t)n);
        return;
    }

    // PTY echo is OFF on this session (set at spawn), so what we read is the
    // command's actual output followed by our sentinel line. Funnel through
    // tail_buf to handle a sentinel that straddles read() boundaries.
    tail_append(s, e->pty_buf, (size_t)n);

    ssize_t found = find_sentinel(s);
    if (found < 0) {
        // Hold back the trailing (sentinel_len - 1) bytes — they could be the
        // start of the sentinel arriving in the next read.
        size_t keep = s->sentinel_len > 0 ? s->sentinel_len - 1 : 0;
        size_t emit = s->tail_len > keep ? s->tail_len - keep : 0;
        if (emit > 0) {
            send_output_bytes(e, s, s->tail_buf, emit);
            memmove(s->tail_buf, s->tail_buf + emit, s->tail_len - emit);
            s->tail_len -= emit;
        }
        return;
    }

    // Strict result-line parse: require "<sentinel>:<int>\r?\n". Anything
    // else (e.g. a sentinel-shaped string in user output without the suffix)
    // is treated as ordinary output and we keep scanning past it.
    size_t after = (size_t)found + s->sentinel_len;
    int reject = 0;
    int has_code = 0, exit_code = 0;
    size_t line_end = 0;  // byte index of the terminating \n

    if (after >= s->tail_len) {
        // Could still be ours — wait for more bytes.
        // Fall through to "hold" path below.
    } else if (s->tail_buf[after] != ':') {
        reject = 1;
    } else {
        size_t p = after + 1;
        int sign = 1;
        if (p < s->tail_len && s->tail_buf[p] == '-') { sign = -1; p++; }
        long v = 0; int any = 0;
        while (p < s->tail_len && s->tail_buf[p] >= '0' && s->tail_buf[p] <= '9') {
            v = v * 10 + (s->tail_buf[p] - '0'); p++; any = 1;
        }
        if (!any) {
            reject = 1;
        } else if (p >= s->tail_len) {
            // Need more bytes for the terminator — fall through to hold.
        } else if (s->tail_buf[p] == '\r' && p + 1 >= s->tail_len) {
            // Saw \r, need \n — hold.
        } else if (s->tail_buf[p] == '\n' || (s->tail_buf[p] == '\r' && s->tail_buf[p + 1] == '\n')) {
            has_code = 1;
            exit_code = (int)(sign * v);
            line_end = (s->tail_buf[p] == '\r') ? p + 1 : p;
        } else {
            reject = 1;  // garbage after digits — not our line
        }
    }

    if (reject) {
        // Treat this sentinel position as ordinary output and resume scanning
        // after the first byte of the false candidate.
        size_t skip = (size_t)found + 1;
        send_output_bytes(e, s, s->tail_buf, skip);
        memmove(s->tail_buf, s->tail_buf + skip, s->tail_len - skip);
        s->tail_len -= skip;
        // Loop hint: caller will run again on next read; if more sentinel
        // candidates already in tail, they'll be discovered then.
        return;
    }

    if (!has_code) {
        // Incomplete line — emit pre-sentinel bytes, keep candidate.
        // Drop the leading separator our printf injected ("\n" or "\r\n").
        size_t trim_back = 0;
        if (found >= 2 && s->tail_buf[found - 2] == '\r' && s->tail_buf[found - 1] == '\n') trim_back = 2;
        else if (found >= 1 && s->tail_buf[found - 1] == '\n') trim_back = 1;
        size_t emit = (size_t)found - trim_back;
        if (emit > 0) send_output_bytes(e, s, s->tail_buf, emit);
        size_t keep = s->tail_len - (size_t)found;
        memmove(s->tail_buf, s->tail_buf + (size_t)found, keep);
        s->tail_len = keep;
        return;
    }

    // Success. Emit pre-sentinel bytes minus the injected separator.
    size_t trim_back = 0;
    if (found >= 2 && s->tail_buf[found - 2] == '\r' && s->tail_buf[found - 1] == '\n') trim_back = 2;
    else if (found >= 1 && s->tail_buf[found - 1] == '\n') trim_back = 1;
    size_t pre = (size_t)found - trim_back;
    if (pre > 0) send_output_bytes(e, s, s->tail_buf, pre);

    (void)line_end;  // bytes after the sentinel line are silently dropped (they shouldn't exist).
    send_step_done(e, s, has_code, exit_code, /*alive=*/1, /*timedOut=*/0);
    run_finish(s);
}

// ── Command dispatch ────────────────────────────────────────────────────────

static int handle_command(edge_t *e, const char *msg, size_t msg_len) {
    const char *type = NULL; size_t type_len = 0;
    if (!json_str(msg, msg_len, "type", &type, &type_len)) return 0;

    const char *bid = NULL; size_t bid_len = 0;
    int has_bid = json_str(msg, msg_len, "blockId", &bid, &bid_len);
    if (has_bid && !is_valid_id(bid, bid_len))
        return send_error(e, NULL, 0, NULL, 0, "INVALID_BLOCK_ID",
                          "blockId must be 1-64 chars of [A-Za-z0-9_.-]");

    #define IS(s) (type_len == sizeof(s) - 1 && memcmp(type, s, sizeof(s) - 1) == 0)

    if (IS("run")) {
        // Sentinel-bracketed exec. Backend never wraps; bridge owns the dance.
        // Required fields: sessionId ("new" or UUID), blockId, cmdB64.
        const char *sid = NULL; size_t sid_len = 0;
        if (!json_str(msg, msg_len, "sessionId", &sid, &sid_len))
            return send_error(e, NULL, 0, NULL, 0, "MISSING_SESSION_ID", "run requires sessionId");
        if (!has_bid || bid_len == 0)
            return send_error(e, NULL, 0, NULL, 0, "MISSING_BLOCK_ID", "run requires blockId");

        // `cmd` is base64-encoded shell text. Avoids JSON-escape ambiguity in
        // our minimal parser (no \" / \uXXXX support) and keeps binary-safe.
        const char *cmd_b64 = NULL; size_t cmd_b64_len = 0;
        if (!json_str(msg, msg_len, "cmdB64", &cmd_b64, &cmd_b64_len))
            return send_error(e, NULL, 0, bid, bid_len, "MISSING_CMD", "run requires cmdB64");
        char *cmd = malloc(cmd_b64_len + 4);
        if (!cmd) return send_error(e, NULL, 0, bid, bid_len, "OOM", "out of memory");
        size_t cmd_len = mg_base64_decode(cmd_b64, cmd_b64_len, cmd, cmd_b64_len + 4);
        if (cmd_len == 0 && cmd_b64_len > 0) {
            free(cmd);
            return send_error(e, NULL, 0, bid, bid_len, "INVALID_BASE64", "cmdB64 is not valid base64");
        }

        // Resolve / allocate session.
        session_t *s = NULL;
        int created = 0;
        int is_new = (sid_len == 3 && memcmp(sid, "new", 3) == 0);
        if (is_new) {
            s = free_slot(e);
            if (!s) { free(cmd); return send_error(e, NULL, 0, bid, bid_len, "MAX_SESSIONS", "max 16 concurrent sessions"); }
            // Paths can legitimately contain JSON-escaped bytes; decode properly.
            char cwd_buf[1024]; cwd_buf[0] = '\0'; size_t cwd_len = 0;
            int has_cwd = json_str_decoded(msg, msg_len, "cwd", cwd_buf, sizeof(cwd_buf), &cwd_len);
            if (has_cwd) {
                // Validate up front so a bad path surfaces as ERROR before we
                // spawn a doomed PTY (otherwise chdir silently fails in child).
                struct stat st;
                if (stat(cwd_buf, &st) != 0 || !S_ISDIR(st.st_mode)) {
                    free(cmd);
                    return send_error(e, NULL, 0, bid, bid_len, "INVALID_CWD", "cwd does not exist or is not a directory");
                }
            }
            if (bridge_pty_spawn(&s->pty, DEFAULT_SHELL, has_cwd ? cwd_buf : NULL, /*no_echo=*/1) != 0) {
                free(cmd);
                return send_error(e, NULL, 0, bid, bid_len, "SPAWN_FAILED", "failed to spawn PTY");
            }
            gen_uuid_v4(s->session_id);
            s->active = 1;
            s->state = SESS_IDLE;
            s->tail_len = 0;
            s->todo_id_len = 0;
            s->todo_id[0] = '\0';
            s->last_active_ms = monotonic_ms();
            created = 1;
            fprintf(stderr, "PTY spawned %s (run)\n", s->session_id);
        } else {
            if (!is_valid_uuid(sid, sid_len)) { free(cmd); return send_error(e, NULL, 0, bid, bid_len, "INVALID_SESSION_ID", "sessionId must be \"new\" or a UUID"); }
            s = find_session(e, sid, sid_len);
            if (!s) { free(cmd); return send_error(e, sid, sid_len, bid, bid_len, "SESSION_NOT_FOUND", "no session for sessionId"); }
            if (s->state == SESS_RUNNING) { free(cmd); return send_error(e, sid, sid_len, bid, bid_len, "SESSION_BUSY", "session already running a step"); }
        }

        // Helper: on a fatal error after the new session was spawned, free
        // the slot so it doesn't leak. No-op for resumed sessions.
        #define RUN_FAIL_CLEANUP() do { \
            if (created) { bridge_pty_close(&s->pty); s->active = 0; s->state = SESS_IDLE; } \
        } while (0)

        // Update opaque echo label from this RUN. Validated charset (same as
        // blockId) so it's safe to interpolate raw with %s. Absent ⇒ keep the
        // existing value; explicit "" ⇒ clear.
        const char *utid = NULL; size_t utid_len = 0;
        if (json_str(msg, msg_len, "todoId", &utid, &utid_len)) {
            if (utid_len > 0 && !is_valid_id(utid, utid_len)) {
                free(cmd); RUN_FAIL_CLEANUP();
                return send_error(e, NULL, 0, bid, bid_len, "INVALID_TODO_ID",
                                  "todoId must be 1-64 chars of [A-Za-z0-9_.-]");
            }
            memcpy(s->todo_id, utid, utid_len);
            s->todo_id[utid_len] = '\0';
            s->todo_id_len = utid_len;
        }

        // Stash per-step routing on the session.
        size_t bn = bid_len < BLOCK_ID_CAP ? bid_len : BLOCK_ID_CAP;
        memcpy(s->run_block_id, bid, bn);
        s->run_block_id[bn] = '\0';
        s->run_block_id_len = bn;

        s->sentinel_len = gen_sentinel(s->sentinel, sizeof(s->sentinel));
        long timeout_ms = 0;
        json_int(msg, msg_len, "timeoutMs", &timeout_ms);
        // Cap to ~1 year so monotonic_ms() + timeout can't overflow int64_t.
        if (timeout_ms > 365LL * 24 * 60 * 60 * 1000) timeout_ms = 365LL * 24 * 60 * 60 * 1000;
        s->deadline_ms = timeout_ms > 0 ? monotonic_ms() + timeout_ms : 0;

        // Wrapper: brace-group tolerates trailing operators in user input;
        // printf with explicit \n on both sides makes the sentinel its own line.
        size_t wrapped_cap = (size_t)cmd_len + s->sentinel_len + 64;
        char *wrapped = malloc(wrapped_cap);
        if (!wrapped) { free(cmd); RUN_FAIL_CLEANUP(); return send_error(e, NULL, 0, bid, bid_len, "OOM", "out of memory"); }
        int wn = snprintf(wrapped, wrapped_cap,
            "{ %.*s\n}; __RC=$?; printf '\\n%s:%%d\\n' \"$__RC\"\n",
            (int)cmd_len, cmd, s->sentinel);
        free(cmd);
        if (wn <= 0 || (size_t)wn >= wrapped_cap) {
            free(wrapped);
            RUN_FAIL_CLEANUP();
            return send_error(e, NULL, 0, bid, bid_len, "INTERNAL", "wrapper too large");
        }

        s->state = SESS_RUNNING;
        s->tail_len = 0;
        s->last_active_ms = monotonic_ms();
        s->last_pause_poll_ms = s->last_active_ms;
        s->pause_consec_ticks = 0;

        send_run_started(e, s, created);

        if (bridge_pty_write_all(&s->pty, wrapped, (size_t)wn) != 0) {
            free(wrapped);
            // STEP_DONE is the terminal response (RUN_STARTED was already sent);
            // a separate ERROR would race against the resolved promise. Log only.
            fprintf(stderr, "PTY_WRITE_FAILED for session %s\n", s->session_id);
            send_step_done(e, s, /*has_code=*/0, 0, /*alive=*/0, /*timedOut=*/0);
            run_finish(s);
            RUN_FAIL_CLEANUP();
            return 0;
        }
        free(wrapped);
        #undef RUN_FAIL_CLEANUP

    } else if (IS("input")) {
        // Forward raw stdin bytes — used to resume a paused RUN. The bridge
        // doesn't track which RUN consumes the bytes; the PTY/kernel/shell do.
        // Optional `requestId` is echoed via ACK on success or ERROR on failure
        // so the caller can correlate (e.g. "session already died").
        const char *rid = NULL; size_t rid_len = 0;
        int has_rid = json_str(msg, msg_len, "requestId", &rid, &rid_len)
                      && rid_len > 0 && is_valid_id(rid, rid_len);

        const char *sid = NULL; size_t sid_len = 0;
        if (!json_str(msg, msg_len, "sessionId", &sid, &sid_len))
            return has_rid ? send_req_error(e, NULL, 0, rid, rid_len, "MISSING_SESSION_ID", "input requires sessionId")
                           : send_error(e, NULL, 0, NULL, 0, "MISSING_SESSION_ID", "input requires sessionId");
        if (!is_valid_uuid(sid, sid_len))
            return has_rid ? send_req_error(e, NULL, 0, rid, rid_len, "INVALID_SESSION_ID", "sessionId must be a UUID")
                           : send_error(e, NULL, 0, NULL, 0, "INVALID_SESSION_ID", "sessionId must be a UUID");
        session_t *s = find_session(e, sid, sid_len);
        if (!s)
            return has_rid ? send_req_error(e, sid, sid_len, rid, rid_len, "SESSION_NOT_FOUND", "no session for sessionId")
                           : send_error(e, sid, sid_len, NULL, 0, "SESSION_NOT_FOUND", "no session for sessionId");

        const char *b64 = NULL; size_t b64_len = 0;
        if (!json_str(msg, msg_len, "data", &b64, &b64_len))
            return has_rid ? send_req_error(e, sid, sid_len, rid, rid_len, "MISSING_DATA", "input requires data")
                           : send_error(e, sid, sid_len, NULL, 0, "MISSING_DATA", "input requires data");
        if (b64_len / 4 * 3 > BUF_SIZE)
            return has_rid ? send_req_error(e, sid, sid_len, rid, rid_len, "INPUT_TOO_LARGE", "input exceeds 4096 bytes")
                           : send_error(e, sid, sid_len, NULL, 0, "INPUT_TOO_LARGE", "input exceeds 4096 bytes");

        char decoded[BUF_SIZE + 4];
        size_t dec_len = mg_base64_decode(b64, b64_len, decoded, sizeof(decoded));
        if (dec_len == 0 && b64_len > 0)
            return has_rid ? send_req_error(e, sid, sid_len, rid, rid_len, "INVALID_BASE64", "data is not valid base64")
                           : send_error(e, sid, sid_len, NULL, 0, "INVALID_BASE64", "data is not valid base64");

        if (bridge_pty_write_all(&s->pty, decoded, dec_len) != 0) {
            fprintf(stderr, "PTY write error\n");
            return has_rid ? send_req_error(e, sid, sid_len, rid, rid_len, "PTY_WRITE_FAILED", "PTY write failed; session may have died")
                           : 0;
        }
        s->last_active_ms = monotonic_ms();
        // Input consumes the prompt: process leaves n_tty_read on the next
        // tick anyway, but reset the counter eagerly to avoid a stale tick
        // re-confirming on the same blocked-read.
        s->pause_consec_ticks = 0;

        if (has_rid) send_ack(e, rid, rid_len);

    } else if (IS("signal")) {
        // Send a Unix signal to the foreground process group of the session's
        // PTY. Default SIGINT — cancels the running command without tearing
        // down the session. The wrapper's sentinel still fires, so the
        // in-flight RUN resolves naturally via STEP_DONE.
        const char *rid = NULL; size_t rid_len = 0;
        int has_rid = json_str(msg, msg_len, "requestId", &rid, &rid_len)
                      && rid_len > 0 && is_valid_id(rid, rid_len);

        const char *sid = NULL; size_t sid_len = 0;
        if (!json_str(msg, msg_len, "sessionId", &sid, &sid_len))
            return has_rid ? send_req_error(e, NULL, 0, rid, rid_len, "MISSING_SESSION_ID", "signal requires sessionId")
                           : send_error(e, NULL, 0, NULL, 0, "MISSING_SESSION_ID", "signal requires sessionId");
        if (!is_valid_uuid(sid, sid_len))
            return has_rid ? send_req_error(e, NULL, 0, rid, rid_len, "INVALID_SESSION_ID", "sessionId must be a UUID")
                           : send_error(e, NULL, 0, NULL, 0, "INVALID_SESSION_ID", "sessionId must be a UUID");
        session_t *s = find_session(e, sid, sid_len);
        if (!s)
            return has_rid ? send_req_error(e, sid, sid_len, rid, rid_len, "SESSION_NOT_FOUND", "no session for sessionId")
                           : send_error(e, sid, sid_len, NULL, 0, "SESSION_NOT_FOUND", "no session for sessionId");

        // Resolve signal name. Default SIGINT.
        // For SIGINT we write Ctrl-C (\x03) to the PTY master — the kernel TTY
        // line discipline delivers SIGINT to the foreground process group only,
        // leaving the bash shell alive (so the wrapper's sentinel still fires
        // and the in-flight RUN resolves via STEP_DONE).
        // SIGTERM/SIGKILL go directly to the shell pid via kill() — these tear
        // the session down (caller's choice).
        enum { SIG_INT_VIA_TTY, SIG_TERM_VIA_KILL, SIG_KILL_VIA_KILL } mode = SIG_INT_VIA_TTY;
        const char *sname = NULL; size_t sname_len = 0;
        if (json_str(msg, msg_len, "signal", &sname, &sname_len)) {
            if (sname_len == 6 && memcmp(sname, "SIGINT", 6) == 0)       mode = SIG_INT_VIA_TTY;
            else if (sname_len == 7 && memcmp(sname, "SIGTERM", 7) == 0) mode = SIG_TERM_VIA_KILL;
            else if (sname_len == 7 && memcmp(sname, "SIGKILL", 7) == 0) mode = SIG_KILL_VIA_KILL;
            else return has_rid ? send_req_error(e, sid, sid_len, rid, rid_len, "INVALID_SIGNAL", "signal must be SIGINT, SIGTERM or SIGKILL")
                                : send_error(e, sid, sid_len, NULL, 0, "INVALID_SIGNAL", "signal must be SIGINT, SIGTERM or SIGKILL");
        }

        int ok;
        if (mode == SIG_INT_VIA_TTY) {
            ok = bridge_pty_write_all(&s->pty, "\x03", 1) == 0;
        } else {
            ok = bridge_pty_signal(&s->pty, mode == SIG_KILL_VIA_KILL ? 9 : 15) == 1;
        }
        if (!ok)
            return has_rid ? send_req_error(e, sid, sid_len, rid, rid_len, "SIGNAL_FAILED", "signal delivery failed; session may have died")
                           : 0;

        if (has_rid) send_ack(e, rid, rid_len);

    } else if (IS("close")) {
        const char *sid = NULL; size_t sid_len = 0;
        if (!json_str(msg, msg_len, "sessionId", &sid, &sid_len))
            return send_error(e, NULL, 0, NULL, 0, "MISSING_SESSION_ID", "close requires sessionId");
        if (!is_valid_uuid(sid, sid_len))
            return send_error(e, NULL, 0, NULL, 0, "INVALID_SESSION_ID", "sessionId must be a UUID");
        session_t *s = find_session(e, sid, sid_len);
        if (!s)
            return send_error(e, sid, sid_len, NULL, 0, "SESSION_NOT_FOUND", "no session for sessionId");
        int force = 0;
        json_bool(msg, msg_len, "force", &force);
        if (force) {
            bridge_pty_signal(&s->pty, /*SIGKILL=*/9);
        } else {
            // Best-effort gentle close. EXIT will arrive via reap.
            (void)bridge_pty_write_all(&s->pty, "exit\n", 5);
        }

    } else if (IS("tool_catalog")) {
        // Server pushed the shell-command catalog; scan and reply.
        const char *entries = NULL; size_t entries_len = 0;
        if (!json_str(msg, msg_len, "entries", &entries, &entries_len)) return 0;

        // Unescape JSON \t, \n, \\, \" in place (we own a decoded copy).
        char *buf = malloc(entries_len + 1);
        if (!buf) return 0;
        size_t w = 0;
        for (size_t i = 0; i < entries_len; i++) {
            char c = entries[i];
            if (c == '\\' && i + 1 < entries_len) {
                char n = entries[++i];
                switch (n) {
                    case 't':  buf[w++] = '\t'; break;
                    case 'n':  buf[w++] = '\n'; break;
                    case 'r':  buf[w++] = '\r'; break;
                    case '\\': buf[w++] = '\\'; break;
                    case '"':  buf[w++] = '"';  break;
                    case '/':  buf[w++] = '/';  break;
                    default:   buf[w++] = n;    break;
                }
            } else {
                buf[w++] = c;
            }
        }
        buf[w] = '\0';

        char *out = malloc(MAX_MSG);
        if (!out) { free(buf); return 0; }
        int n = bridge_scan_tools(buf, w, out, MAX_MSG);
        if (n > 0) {
            send_json(e, out, (size_t)n);
            fprintf(stderr, "Scanned tools, %d bytes reported\n", n);
        } else {
            fprintf(stderr, "Tool scan failed (overflow or empty)\n");
        }
        free(out);
        free(buf);
    }

    #undef IS
    return 0;
}

// ── Main loop ───────────────────────────────────────────────────────────────

// Per-tick session servicing: reap, deadline, pause-probe, idle-GC, PTY drain.
// PTY master fds are non-blocking (set by bridge_pty_spawn), so reads here
// return 0 immediately when no data is available.
static void service_sessions(edge_t *e) {
    int64_t now = monotonic_ms();

    // Reap exited shells; if a step was in flight, surface STEP_DONE first
    // so the backend's pending RUN promise settles cleanly.
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &e->sessions[i];
        if (!s->active) continue;
        int code;
        if (bridge_pty_reap(&s->pty, &code)) {
            if (s->state == SESS_RUNNING) {
                if (s->tail_len > 0) {
                    send_output_bytes(e, s, s->tail_buf, s->tail_len);
                    s->tail_len = 0;
                }
                send_step_done(e, s, /*has_code=*/1, code, /*alive=*/0, /*timedOut=*/0);
                run_finish(s);
            }
            send_exit(e, s, code);
            bridge_pty_close(&s->pty);
            s->active = 0;
        }
    }

    // Per-step deadline. Don't kill the shell — just settle the RUN.
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &e->sessions[i];
        if (!s->active || s->state != SESS_RUNNING || s->deadline_ms == 0) continue;
        if (now < s->deadline_ms) continue;
        if (s->tail_len > 0) {
            send_output_bytes(e, s, s->tail_buf, s->tail_len);
            s->tail_len = 0;
        }
        send_step_done(e, s, /*has_code=*/0, 0, /*alive=*/1, /*timedOut=*/1);
        run_finish(s);
    }

    // Pause detection: poll the wchan probe at PAUSE_POLL_MS cadence; emit
    // STEP_PAUSED once `blocked` has been observed PAUSE_CONFIRM_TICKS times
    // in a row. A single non-blocked tick (e.g. process resumed, or it was a
    // transient pipe_read between bytes) resets the counter.
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &e->sessions[i];
        if (!s->active || s->state != SESS_RUNNING) continue;
        if (now - s->last_pause_poll_ms < PAUSE_POLL_MS) continue;
        s->last_pause_poll_ms = now;

        pid_t fg = 0; int pwd = 0;
        int blocked = bridge_pty_probe_blocked(&s->pty, /*echo_baseline=*/0, &fg, &pwd);
        if (!blocked) { s->pause_consec_ticks = 0; continue; }
        if (++s->pause_consec_ticks != PAUSE_CONFIRM_TICKS) continue;

        if (s->tail_len > 0) {
            send_output_bytes(e, s, s->tail_buf, s->tail_len);
            s->tail_len = 0;
        }
        send_step_paused(e, s, pwd);
        fprintf(stderr, "RUN paused (waiting for stdin): %s fg=%d pwd=%d\n",
                s->run_block_id, (int)fg, pwd);
    }

    // Idle-session GC.
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &e->sessions[i];
        if (!s->active || s->state == SESS_RUNNING) continue;
        if (now - s->last_active_ms < IDLE_TIMEOUT_MS) continue;
        fprintf(stderr, "Idle GC: killing %s (idle %lld ms)\n",
                s->session_id, (long long)(now - s->last_active_ms));
        bridge_pty_signal(&s->pty, /*SIGKILL=*/9);
        s->last_active_ms = now;
    }

    // Drain PTY masters (non-blocking; returns 0 on EAGAIN).
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &e->sessions[i];
        if (s->active) forward_pty_output(e, s);
    }
}

static void on_ws_event(struct mg_connection *c, int ev, void *ev_data) {
    edge_t *e = c->fn_data;
    if (ev == MG_EV_ERROR) {
        fprintf(stderr, "WS error: %s\n", (char *)ev_data);
        e->rc = 1; e->done = 1;
    }
    else if (ev == MG_EV_CLOSE)   { e->ws = NULL; e->done = 1; }
    else if (ev == MG_EV_WS_CTL) {
        struct mg_ws_message *wm = ev_data;
        if (wm->flags & 8) {  // close opcode
            uint16_t code = 0;
            if (wm->data.len >= 2)
                code = ((uint8_t)wm->data.buf[0] << 8) | (uint8_t)wm->data.buf[1];
            fprintf(stderr, "WS close: code=%u reason=%.*s\n",
                    code,
                    (int)(wm->data.len > 2 ? wm->data.len - 2 : 0),
                    wm->data.len > 2 ? wm->data.buf + 2 : "");
        }
    }
    else if (ev == MG_EV_WS_OPEN) { noise_ws_start(&e->noise, c); }
    else if (ev == MG_EV_WS_MSG) {
        struct mg_ws_message *wm = ev_data;
        long n = noise_ws_recv(&e->noise,
                               (uint8_t *)wm->data.buf, wm->data.len,
                               e->msg_buf, sizeof(e->msg_buf));
        if (n < 0) { e->rc = 1; e->done = 1; return; }
        if (n == 0) {
            // Handshake just completed → send auth + identity once.
            char auth[1024];
            int an = mg_snprintf(auth, sizeof(auth),
                "{%m:%m,%m:%m,%m:%m}",
                MG_ESC("type"),     MG_ESC("auth"),
                MG_ESC("deviceId"), MG_ESC(e->device_id),
                MG_ESC("secret"),   MG_ESC(e->device_secret));
            send_json(e, auth, (size_t)an);
            // Identity is deferred — see edge_t.identity_sent / auth_sent_ms.
            e->auth_sent_ms = monotonic_ms();
            return;
        }
        handle_command(e, (const char *)e->msg_buf, (size_t)n);
    }
    else if (ev == MG_EV_POLL) {
        if (e->noise.handshake_done && !e->identity_sent &&
            e->auth_sent_ms != 0 && monotonic_ms() - e->auth_sent_ms >= 100) {
            char id[1024];
            int il = bridge_identity_json(id, sizeof(id), 0);
            if (il > 0) send_json(e, id, (size_t)il);
            e->identity_sent = 1;
            fprintf(stderr, "Identified\n");
        }
        service_sessions(e);
    }
}

static int run(edge_t *e, const char *device_id, const char *device_secret,
               const char *url, const uint8_t pubkey[32]) {
    e->device_id = device_id;
    e->device_secret = device_secret;
    if (noise_ws_init(&e->noise, pubkey) != 0) return -1;
    mg_mgr_init(&e->mgr);
    e->ws = mg_ws_connect(&e->mgr, url, on_ws_event, e, NULL);
    if (!e->ws) { mg_mgr_free(&e->mgr); return -1; }
    while (!e->done) mg_mgr_poll(&e->mgr, 50);
    mg_mgr_free(&e->mgr);
    noise_ws_wipe(&e->noise);
    return e->rc;
}

// ── Args / env ──────────────────────────────────────────────────────────────

static int parse_pubkey_hex(const char *hex, uint8_t out[32]) {
    if (!hex || strlen(hex) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

int main(int argc, char **argv) {
    // If a new binary was staged next to us (by a prior `exec` update command),
    // swap it in before we do anything else. See update.h.
    bridge_update_swap_on_start(argv[0]);

    // Subcommand dispatch (must come before option parsing so `bridge login -h`
    // shows the login-specific usage).
    if (argc >= 2 && strcmp(argv[1], "login") == 0) {
        return cmd_login(argc - 1, argv + 1);
    }
    if (argc >= 2 && strcmp(argv[1], "enroll") == 0) {
        return cmd_enroll(argc - 1, argv + 1);
    }
    if (argc >= 2 && strcmp(argv[1], "whoami") == 0) {
        return cmd_whoami(argc - 1, argv + 1);
    }
    if (argc >= 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "version") == 0)) {
        printf("%s\n", BRIDGE_VERSION);
        return 0;
    }

    const char *host = NULL, *port_s = NULL, *pubkey_hex = NULL;
    ko_longopt_t longopts[] = {
        { "help",          ko_no_argument,       'h' },
        { "host",          ko_required_argument, 'H' },
        { "port",          ko_required_argument, 'p' },
        { "server-pubkey", ko_required_argument, 'k' },
        { 0, 0, 0 }
    };
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "hH:p:k:", longopts)) >= 0) {
        if      (c == 'h') { print_help(); return 0; }
        else if (c == 'H') host = opt.arg;
        else if (c == 'p') port_s = opt.arg;
        else if (c == 'k') pubkey_hex = opt.arg;
        else cli_parse_error("bridge", USAGE_MAIN, argc, argv, &opt, c);
    }

    // Load saved device credentials from `bridge login`
    login_credentials_t saved_creds;
    memset(&saved_creds, 0, sizeof(saved_creds));
    (void)login_load_credentials(&saved_creds);

    if (!saved_creds.device_id[0] || !saved_creds.device_secret[0]) {
        fprintf(stderr, "No device credentials found. Run `bridge login [--device-name NAME]` first.\n\n");
        print_help();
        return 1;
    }

    if (!host) host = getenv("EDGE_HOST");
    if (!host) host = DEFAULT_HOST;

    if (!port_s) port_s = getenv("EDGE_PORT");
    uint16_t port = DEFAULT_PORT;
    if (port_s) {
        int p = atoi(port_s);
        if (p > 0 && p <= 65535) port = (uint16_t)p;
    }

    if (!pubkey_hex) pubkey_hex = getenv("EDGE_SERVER_PUBKEY");
    if (!pubkey_hex) pubkey_hex = DEFAULT_SERVER_PUBKEY_HEX;

    uint8_t server_pubkey[32];
    if (parse_pubkey_hex(pubkey_hex, server_pubkey) != 0) {
        fprintf(stderr, "invalid server pubkey (need 64 hex chars)\n");
        return 1;
    }

    fprintf(stderr, "Connecting to %s:%u (noise) as device %s...\n", host, (unsigned)port, saved_creds.device_id);

    edge_t *e = calloc(1, sizeof(*e));
    if (!e) return 1;

    char url[256];
    mg_snprintf(url, sizeof(url), "ws://%s:%u%s", host, (unsigned)port, DEFAULT_PATH);
    int rc = run(e, saved_creds.device_id, saved_creds.device_secret, url, server_pubkey);

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (e->sessions[i].active) bridge_pty_close(&e->sessions[i].pty);
    }
    free(e);

    if (rc != 0) fprintf(stderr, "Disconnected\n");
    return rc == 0 ? 0 : 1;
}
