// TODOforAI Bridge — C runtime. TCP → WebSocket → Noise_NX → PTY relay.
//
// Protocol (inside Noise transport):
//   First encrypted msg (edge→server):
//     {"type":"auth","deviceId":"dev_...","secret":"..."}
//   Then v2 control messages (JSON). The bridge knows ONE identifier:
//   `sessionId` (UUID it mints when a PTY is spawned via a RUN that omits
//   `sessionId`). It has no notion of TODOs — that mapping lives in the
//   backend. `blockId` rides on RUN frames as an RPC correlation key.
//   A RUN without `sessionId` is one-shot: the PTY auto-closes on STEP_DONE
//   (unless STEP_PAUSED upgraded it to a persistent session).
//     → {"type":"identity","data":{...}}
//     ← {"type":"run","sessionId":"uuid"?,"blockId":"...","cmdB64":"...","cwd":"...","timeoutMs":N}
//     → {"type":"run_started","sessionId":"uuid","blockId":"...","created":bool}
//     → {"type":"output","sessionId":"uuid","blockId":"...","data":"base64"}
//     → {"type":"step_paused","sessionId":"uuid","blockId":"...","passwordPrompt":bool}
//     → {"type":"step_done","sessionId":"uuid","blockId":"...","exitCode":N|null,"timedOut":bool}
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
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>   // WSAPoll, struct pollfd, POLL* — must precede windows.h
#  include <windows.h>
#  define poll WSAPoll
// Portable byte-substring search: glibc has memmem; mingw/MSVCRT does not.
static void *memmem_compat(const void *h, size_t hl, const void *n, size_t nl) {
    if (nl == 0) return (void *)h;
    if (hl < nl) return NULL;
    const uint8_t *hp = h, *np = n;
    for (size_t i = 0; i + nl <= hl; i++) {
        if (hp[i] == np[0] && memcmp(hp + i, np, nl) == 0) return (void *)(hp + i);
    }
    return NULL;
}
#  define memmem(h, hl, n, nl) memmem_compat((h), (hl), (n), (nl))
#else
#  include <poll.h>
#  include <sys/resource.h>
#  include <unistd.h>
#endif

#include "args.h"      // ketopt + cli_usage helpers
#include "identity.h"  // BRIDGE_VERSION
#include "json.h"
#include "noise.h"     // noise_random
#include "noise_ws.h"
#include "ws.h"
#include "pty.h"
#include "subcmd.h"
#include "tools.h"
#include "update.h"
#include "login.h"

// ── Defaults ────────────────────────────────────────────────────────────────

#define DEFAULT_HOST         LOGIN_DEFAULT_BACKEND_HOST
// Plain HTTP port — bridge has no TLS client; Noise provides end-to-end crypto.
#define DEFAULT_PORT         80
#define DEFAULT_PATH         "/ws/v2/bridge"
#ifdef _WIN32
// pty_win.c resolves NULL → $BRIDGE_SHELL → bash.exe (PATH) → Git Bash → cmd.exe.
#define DEFAULT_SHELL        NULL
#else
#define DEFAULT_SHELL        "/bin/sh"
#endif
#define BUF_SIZE             4096
// Soft cap on concurrent PTYs. Overridable at runtime via BRIDGE_MAX_SESSIONS;
// see `g_max_sessions` and `resolve_max_sessions()`. Each slot is ~4.5 KB in
// the bridge plus one shell process + PTY pair in the kernel — the real
// ceiling is the fd limit (see `bump_fd_limit()`), not RAM.
#define DEFAULT_MAX_SESSIONS 256
#define SESSION_ID_LEN       36
#define BLOCK_ID_CAP         64
#define MAX_MSG              (64 * 1024)

// Server's Noise static public key — shared with sandbox/browser CLIs via
// LOGIN_DEFAULT_BACKEND_PUBKEY. Overridable via NOISE_BACKEND_PUBKEY env
// or --server-pubkey flag.
#define DEFAULT_SERVER_PUBKEY_HEX LOGIN_DEFAULT_BACKEND_PUBKEY

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
    // PTY identity. UUID v4 minted by the bridge whenever a RUN spawns a
    // fresh PTY. Authoritative routing key; the bridge looks up sessions by
    // this.
    char session_id[SESSION_ID_LEN + 1];
    bridge_pty_t pty;
    // One-shot: the RUN that spawned this session omitted `sessionId`, so
    // the bridge owns lifecycle and will close the PTY on STEP_DONE. Cleared
    // if the run pauses (STEP_PAUSED) — at that point the agent has the
    // minted sessionId and the session becomes persistent for resume.
    int one_shot;

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
    // Monotonic ms of last activity (spawn / INPUT / OUTPUT / STEP_DONE).
    // Used as LRU key when evicting an idle session to make room for a new
    // RUN once the array is full. SESS_RUNNING sessions are never evicted.
    int64_t last_active_ms;
    // Pause detection (RUN only): poll the wchan probe every PAUSE_POLL_MS
    // and emit STEP_PAUSED once `blocked` is observed PAUSE_CONFIRM_TICKS
    // times in a row. Any non-blocked tick resets the counter, so resumption
    // (input arrived → process leaves n_tty_read) is detected implicitly.
    int64_t last_pause_poll_ms;
    int     pause_consec_ticks;
    // Monotonic ms stamp set AFTER bridge_pty_write_all returns (RUN cmd or
    // INPUT). Bridge is single-threaded, so the probe can't run during the
    // write — only the trailing ldisc drain (≤4KB) is a false-pause window.
    // Probe waits INPUT_GRACE_MS past this stamp before it may fire.
    int64_t last_input_ms;
} session_t;

// Pause poll cadence + confirmation. 2 ticks at 250 ms ⇒ ~250-500 ms latency
// to detect a real prompt; FP rate ~1-2% (vs. ~30-60% for output-quiescence).
#define PAUSE_POLL_MS        250
#define PAUSE_CONFIRM_TICKS  2
// Grace period AFTER bridge_pty_write_all returns before pause detection may
// fire. The bridge is single-threaded so the probe can't run during the
// write itself; the only false-pause window is the trailing line-discipline
// drain (≤ Linux n_tty buffer ~4KB, drains at >>1MB/s → tens of ms in
// practice). Sized generously to cover slow VMs while staying well below
// PAUSE_POLL_MS+PAUSE_CONFIRM_TICKS, so latency for genuine prompts is
// unaffected (still ~500ms after the wrapped command's last byte).
#define INPUT_GRACE_MS       500

typedef struct {
    ws_t ws;
    noise_ws_t noise;
    const char *device_id;
    const char *device_secret;
    int done;
    int rc;
    // Auth → identity sequencing. Backend's pre-auth handler awaits
    // validateDevice() asynchronously; if both frames land in one TCP segment
    // (TCP-coalesced into one segment), the second hits the handler with
    // authenticated=false and is rejected as "expected auth". Defer identity
    // until the auth round-trip has had time to settle on the backend.
    int identity_sent;
    int64_t auth_sent_ms;

    // Last disconnect reason — surfaced by main() so users get actionable output
    // instead of a bare "Disconnected".
    uint16_t close_code;
    int      got_close_frame;
    char     close_reason[128];
    char     err_msg[160];

    session_t *sessions;     // heap, length = g_max_sessions
    uint8_t  pty_buf[BUF_SIZE];
    char     b64_buf[BUF_SIZE * 2];
    uint8_t  msg_buf[MAX_MSG];
} edge_t;

// Runtime cap, set once in main() before edge_t is allocated. All loops over
// sessions use this; never read directly before main() resolves it.
static int g_max_sessions = DEFAULT_MAX_SESSIONS;

// ── Helpers ─────────────────────────────────────────────────────────────────

// Record a fatal reason and tear down. Safe to call multiple times — first
// caller wins so the root cause survives the cascade of CLOSE/ERROR events.
static void fail(edge_t *e, const char *fmt, ...) {
    if (!e->err_msg[0]) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(e->err_msg, sizeof e->err_msg, fmt, ap);
        va_end(ap);
    }
    e->rc = 1;
    e->done = 1;
}

static int64_t monotonic_ms(void) {
#ifdef _WIN32
    return (int64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
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
    for (int i = 0; i < g_max_sessions; i++) {
        session_t *s = &e->sessions[i];
        if (s->active && strlen(s->session_id) == sid_len &&
            memcmp(s->session_id, sid, sid_len) == 0) {
            return s;
        }
    }
    return NULL;
}

static session_t *free_slot(edge_t *e) {
    for (int i = 0; i < g_max_sessions; i++) {
        if (!e->sessions[i].active) return &e->sessions[i];
    }
    return NULL;
}

// Forward decls used by evict_lru_idle().
static void send_exit(edge_t *e, session_t *s, int code);

// LRU eviction: when the array is full and a RUN needs a slot, SIGKILL the
// oldest SESS_IDLE session and reclaim it synchronously. SESS_RUNNING is
// never evicted — there's an in-flight step the backend is awaiting.
// Returns the reclaimed slot, or NULL if every slot is busy.
static session_t *evict_lru_idle(edge_t *e) {
    session_t *victim = NULL;
    for (int i = 0; i < g_max_sessions; i++) {
        session_t *s = &e->sessions[i];
        if (!s->active || s->state == SESS_RUNNING) continue;
        if (!victim || s->last_active_ms < victim->last_active_ms) victim = s;
    }
    if (!victim) return NULL;
    fprintf(stderr, "LRU evict: killing %s (idle %lld ms)\n",
            victim->session_id, (long long)(monotonic_ms() - victim->last_active_ms));
    bridge_pty_signal(&victim->pty, /*SIGKILL=*/9);
    // Surface EXIT so the backend can drop its mapping. Synchronous close
    // here (rather than waiting for reap) keeps the slot allocator simple.
    send_exit(e, victim, -9);
    bridge_pty_close(&victim->pty);
    victim->active = 0;
    return victim;
}

static int send_json(edge_t *e, const char *s, size_t n) {
    if (e->ws.closed || !e->noise.handshake_done) return -1;
    if (getenv("BRIDGE_DEBUG_WIRE"))
        fprintf(stderr, "→ send (%zu) %.*s\n", n, (int)(n > 512 ? 512 : n), s);
    return noise_ws_send(&e->noise, &e->ws, (const uint8_t *)s, n);
}

static int jfield_str(char *buf, size_t cap, size_t *u, const char *key, const char *val, long len, int comma) {
    if (comma && json_emit_raw(buf, cap, u, ",", 1) < 0) return -1;
    return json_emit_str(buf, cap, u, key, -1) < 0 || json_emit_raw(buf, cap, u, ":", 1) < 0 || json_emit_str(buf, cap, u, val, len) < 0 ? -1 : 0;
}

static int jfield_raw(char *buf, size_t cap, size_t *u, const char *key, const char *val, int comma) {
    if (comma && json_emit_raw(buf, cap, u, ",", 1) < 0) return -1;
    return json_emit_str(buf, cap, u, key, -1) < 0 || json_emit_raw(buf, cap, u, ":", 1) < 0 || json_emit_raw(buf, cap, u, val, strlen(val)) < 0 ? -1 : 0;
}

static int emit_todo_id(char *buf, size_t cap, size_t *u, const session_t *s) {
    return s->todo_id_len > 0 ? jfield_str(buf, cap, u, "todoId", s->todo_id, (long)s->todo_id_len, 1) : 0;
}

static int send_error(edge_t *e,
                      const char *sid, size_t sid_len,
                      const char *bid, size_t bid_len,
                      const char *code, const char *message) {
    char buf[1024]; size_t u = 0;
    if (json_emit_raw(buf, sizeof buf, &u, "{", 1) < 0 ||
        jfield_str(buf, sizeof buf, &u, "type", "error", -1, 0) < 0 ||
        (sid && jfield_str(buf, sizeof buf, &u, "sessionId", sid, (long)sid_len, 1) < 0) ||
        (bid && jfield_str(buf, sizeof buf, &u, "blockId", bid, (long)bid_len, 1) < 0) ||
        jfield_str(buf, sizeof buf, &u, "code", code, -1, 1) < 0 ||
        jfield_str(buf, sizeof buf, &u, "message", message, -1, 1) < 0 ||
        json_emit_raw(buf, sizeof buf, &u, "}", 1) < 0) return -1;
    send_json(e, buf, u);
    fprintf(stderr, "error %s: %s\n", code, message);
    return 0;
}

// Reply to an INPUT/SIGNAL request that failed. Same as send_error but
// also echoes `requestId` so the backend can settle the right pending call.
static int send_req_error(edge_t *e,
                          const char *sid, size_t sid_len,
                          const char *rid, size_t rid_len,
                          const char *code, const char *message) {
    char buf[1024]; size_t u = 0;
    if (json_emit_raw(buf, sizeof buf, &u, "{", 1) < 0 ||
        jfield_str(buf, sizeof buf, &u, "type", "error", -1, 0) < 0 ||
        (sid && jfield_str(buf, sizeof buf, &u, "sessionId", sid, (long)sid_len, 1) < 0) ||
        jfield_str(buf, sizeof buf, &u, "requestId", rid, (long)rid_len, 1) < 0 ||
        jfield_str(buf, sizeof buf, &u, "code", code, -1, 1) < 0 ||
        jfield_str(buf, sizeof buf, &u, "message", message, -1, 1) < 0 ||
        json_emit_raw(buf, sizeof buf, &u, "}", 1) < 0) return -1;
    send_json(e, buf, u);
    fprintf(stderr, "error %s: %s\n", code, message);
    return 0;
}

static int send_ack(edge_t *e, const char *rid, size_t rid_len) {
    char buf[128]; size_t u = 0;
    if (json_emit_raw(buf, sizeof buf, &u, "{", 1) < 0 ||
        jfield_str(buf, sizeof buf, &u, "type", "ack", -1, 0) < 0 ||
        jfield_str(buf, sizeof buf, &u, "requestId", rid, (long)rid_len, 1) < 0 ||
        json_emit_raw(buf, sizeof buf, &u, "}", 1) < 0) return -1;
    return send_json(e, buf, u);
}

static void send_exit(edge_t *e, session_t *s, int code) {
    char buf[384]; size_t u = 0;
    char code_buf[32]; snprintf(code_buf, sizeof code_buf, "%d", code);
    if (json_emit_raw(buf, sizeof buf, &u, "{", 1) < 0 ||
        jfield_str(buf, sizeof buf, &u, "type", "exit", -1, 0) < 0 ||
        jfield_str(buf, sizeof buf, &u, "sessionId", s->session_id, -1, 1) < 0 ||
        emit_todo_id(buf, sizeof buf, &u, s) < 0 ||
        (s->run_block_id_len > 0 && jfield_str(buf, sizeof buf, &u, "blockId", s->run_block_id, (long)s->run_block_id_len, 1) < 0) ||
        jfield_raw(buf, sizeof buf, &u, "code", code_buf, 1) < 0 ||
        json_emit_raw(buf, sizeof buf, &u, "}", 1) < 0) return;
    send_json(e, buf, u);
    fprintf(stderr, "PTY exited: %s code=%d\n", s->session_id, code);
}

// Emit OUTPUT for `len` bytes of PTY stream. blockId is included only while
// a RUN is in flight (echoed from the RUN frame for backend correlation).
static void send_output_bytes(edge_t *e, session_t *s,
                              const uint8_t *data, size_t len) {
    if (len == 0) return;
    size_t bn = b64_encode(data, len, e->b64_buf, sizeof(e->b64_buf));
    if (bn == 0) return;
    size_t cap = bn + 256;
    char *msg = malloc(cap);
    if (!msg) return;
    size_t u = 0;
    if (json_emit_raw(msg, cap, &u, "{", 1) == 0 &&
        jfield_str(msg, cap, &u, "type", "output", -1, 0) == 0 &&
        jfield_str(msg, cap, &u, "sessionId", s->session_id, -1, 1) == 0 &&
        emit_todo_id(msg, cap, &u, s) == 0 &&
        (!(s->state == SESS_RUNNING && s->run_block_id_len > 0) || jfield_str(msg, cap, &u, "blockId", s->run_block_id, (long)s->run_block_id_len, 1) == 0) &&
        jfield_str(msg, cap, &u, "data", e->b64_buf, (long)bn, 1) == 0 &&
        json_emit_raw(msg, cap, &u, "}", 1) == 0) send_json(e, msg, u);
    free(msg);
}

// Portable accessor for the shell's OS pid (the PTY child).
#ifdef _WIN32
#  define SHELL_PID(s) ((long)(s)->pty.pid)
#else
#  define SHELL_PID(s) ((long)(s)->pty.child_pid)
#endif

static void send_run_started(edge_t *e, session_t *s, int created) {
    char buf[384]; size_t u = 0;
    char pid_buf[24]; snprintf(pid_buf, sizeof pid_buf, "%ld", SHELL_PID(s));
    if (json_emit_raw(buf, sizeof buf, &u, "{", 1) < 0 ||
        jfield_str(buf, sizeof buf, &u, "type", "run_started", -1, 0) < 0 ||
        jfield_str(buf, sizeof buf, &u, "sessionId", s->session_id, -1, 1) < 0 ||
        emit_todo_id(buf, sizeof buf, &u, s) < 0 ||
        jfield_str(buf, sizeof buf, &u, "blockId", s->run_block_id, (long)s->run_block_id_len, 1) < 0 ||
        jfield_raw(buf, sizeof buf, &u, "shellPid", pid_buf, 1) < 0 ||
        jfield_raw(buf, sizeof buf, &u, "created", created ? "true" : "false", 1) < 0 ||
        json_emit_raw(buf, sizeof buf, &u, "}", 1) < 0) return;
    send_json(e, buf, u);
}

// exit_code < 0 ⇒ emit `null`. When the shell died during the step, an EXIT
// frame follows; backend doesn't need a separate `alive` flag on STEP_DONE.
static void send_step_done(edge_t *e, session_t *s, int has_code, int exit_code,
                           int timed_out) {
    char buf[512]; size_t u = 0;
    char rc[24]; snprintf(rc, sizeof rc, has_code ? "%d" : "null", exit_code);
    char pid_buf[24]; snprintf(pid_buf, sizeof pid_buf, "%ld", SHELL_PID(s));
    if (json_emit_raw(buf, sizeof buf, &u, "{", 1) < 0 ||
        jfield_str(buf, sizeof buf, &u, "type", "step_done", -1, 0) < 0 ||
        jfield_str(buf, sizeof buf, &u, "sessionId", s->session_id, -1, 1) < 0 ||
        emit_todo_id(buf, sizeof buf, &u, s) < 0 ||
        jfield_str(buf, sizeof buf, &u, "blockId", s->run_block_id, (long)s->run_block_id_len, 1) < 0 ||
        jfield_raw(buf, sizeof buf, &u, "shellPid", pid_buf, 1) < 0 ||
        jfield_raw(buf, sizeof buf, &u, "exitCode", rc, 1) < 0 ||
        jfield_raw(buf, sizeof buf, &u, "timedOut", timed_out ? "true" : "false", 1) < 0 ||
        json_emit_raw(buf, sizeof buf, &u, "}", 1) < 0) return;
    send_json(e, buf, u);
}

// Bridge → server: "command is blocked waiting for stdin". The PTY stays
// alive and the RUN stays in flight; backend resolves the pending RUN promise
// with `paused:true` so the agent gets the prompt text and can resume by
// sending INPUT on the same sessionId.
// `passwordPrompt` is true when the slave has ECHO disabled (sudo/getpass/ssh).
static void send_step_paused(edge_t *e, session_t *s, long fg_pid, int password_prompt) {
    char buf[512]; size_t u = 0;
    char shell_pid_buf[24]; snprintf(shell_pid_buf, sizeof shell_pid_buf, "%ld", SHELL_PID(s));
    char fg_pid_buf[24]; snprintf(fg_pid_buf, sizeof fg_pid_buf, "%ld", fg_pid);
    if (json_emit_raw(buf, sizeof buf, &u, "{", 1) < 0 ||
        jfield_str(buf, sizeof buf, &u, "type", "step_paused", -1, 0) < 0 ||
        jfield_str(buf, sizeof buf, &u, "sessionId", s->session_id, -1, 1) < 0 ||
        emit_todo_id(buf, sizeof buf, &u, s) < 0 ||
        jfield_str(buf, sizeof buf, &u, "blockId", s->run_block_id, (long)s->run_block_id_len, 1) < 0 ||
        jfield_raw(buf, sizeof buf, &u, "shellPid", shell_pid_buf, 1) < 0 ||
        jfield_raw(buf, sizeof buf, &u, "fgPid", fg_pid_buf, 1) < 0 ||
        jfield_raw(buf, sizeof buf, &u, "passwordPrompt", password_prompt ? "true" : "false", 1) < 0 ||
        json_emit_raw(buf, sizeof buf, &u, "}", 1) < 0) return;
    send_json(e, buf, u);
}

// Reset per-step state. Subsequent PTY bytes (e.g. trailing async output)
// emit OUTPUT without a blockId — the backend routes them to the session.
//
// One-shot sessions (spawned by a RUN with no `sessionId`) are torn down
// here: the agent never asked for a persistent session, so the slot is
// reclaimed eagerly. If the run paused mid-step, `one_shot` was cleared on
// STEP_PAUSED — the session has been "promoted" and survives this finish.
static void run_finish(session_t *s) {
    s->state = SESS_IDLE;
    s->tail_len = 0;
    s->deadline_ms = 0;
    s->run_block_id_len = 0;
    s->run_block_id[0] = '\0';
    s->sentinel_len = 0;
    s->pause_consec_ticks = 0;
    // LRU: command just finished; refresh the activity stamp so this session
    // is the most-recently-used.
    s->last_active_ms = monotonic_ms();
    if (s->one_shot) {
        // The wrapped command finished but the shell is still alive — we
        // own its lifecycle, so SIGKILL it synchronously and reclaim the
        // slot. SIGKILL (not "exit\n") keeps bridge_pty_close's blocking
        // waitpid bounded; same pattern as evict_lru_idle.
        //
        // No EXIT frame: the backend has already settled the agent's
        // promise via STEP_DONE, and backend's EXIT handler is log-only —
        // emitting "code=-9" after every successful one-shot would just be
        // noise that looks like a failure.
        fprintf(stderr, "PTY auto-close %s (one-shot done)\n", s->session_id);
        bridge_pty_signal(&s->pty, /*SIGKILL=*/9);
        bridge_pty_close(&s->pty);
        s->active = 0;
        s->one_shot = 0;
    }
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
    send_step_done(e, s, has_code, exit_code, /*timedOut=*/0);
    run_finish(s);
}

// ── Command dispatch ────────────────────────────────────────────────────────

static int handle_command(edge_t *e, const char *msg, size_t msg_len) {
    const char *type = NULL; size_t type_len = 0;
    if (!json_get_str(msg, msg_len, "type", &type, &type_len)) return 0;

    const char *bid = NULL; size_t bid_len = 0;
    int has_bid = json_get_str(msg, msg_len, "blockId", &bid, &bid_len);
    if (has_bid && !is_valid_id(bid, bid_len))
        return send_error(e, NULL, 0, NULL, 0, "INVALID_BLOCK_ID",
                          "blockId must be 1-64 chars of [A-Za-z0-9_.-]");

    #define IS(s) (type_len == sizeof(s) - 1 && memcmp(type, s, sizeof(s) - 1) == 0)

    if (IS("run")) {
        // Sentinel-bracketed exec. Backend never wraps; bridge owns the dance.
        // Required fields: blockId, cmdB64. `sessionId` is optional — when
        // absent, the bridge spawns a one-shot PTY and auto-closes it on
        // STEP_DONE (kept alive only if STEP_PAUSED fires first).
        const char *sid = NULL; size_t sid_len = 0;
        int has_sid = json_get_str(msg, msg_len, "sessionId", &sid, &sid_len) && sid_len > 0;
        if (!has_bid || bid_len == 0)
            return send_error(e, NULL, 0, NULL, 0, "MISSING_BLOCK_ID", "run requires blockId");

        // `cmd` is base64-encoded shell text. Avoids JSON-escape ambiguity in
        // our minimal parser (no \" / \uXXXX support) and keeps binary-safe.
        const char *cmd_b64 = NULL; size_t cmd_b64_len = 0;
        if (!json_get_str(msg, msg_len, "cmdB64", &cmd_b64, &cmd_b64_len))
            return send_error(e, NULL, 0, bid, bid_len, "MISSING_CMD", "run requires cmdB64");
        char *cmd = malloc(cmd_b64_len + 4);
        if (!cmd) return send_error(e, NULL, 0, bid, bid_len, "OOM", "out of memory");
        size_t cmd_len = b64_decode(cmd_b64, cmd_b64_len, cmd, cmd_b64_len + 4);
        if (cmd_len == 0 && cmd_b64_len > 0) {
            free(cmd);
            return send_error(e, NULL, 0, bid, bid_len, "INVALID_BASE64", "cmdB64 is not valid base64");
        }

        // Resolve / allocate session. Missing sessionId ⇒ spawn one-shot.
        session_t *s = NULL;
        int created = 0;
        if (!has_sid) {
            s = free_slot(e);
            // Array full: evict the LRU idle session to make room. Only RUN
            // sessions (which have an in-flight step) are protected.
            if (!s) s = evict_lru_idle(e);
            if (!s) {
                free(cmd);
                char errmsg[64];
                snprintf(errmsg, sizeof errmsg, "all %d sessions busy", g_max_sessions);
                return send_error(e, NULL, 0, bid, bid_len, "MAX_SESSIONS", errmsg);
            }
            // Paths can legitimately contain JSON-escaped bytes; decode properly.
            char cwd_buf[1024]; cwd_buf[0] = '\0'; size_t cwd_len = 0;
            int has_cwd = json_get_str_decoded(msg, msg_len, "cwd", cwd_buf, sizeof(cwd_buf), &cwd_len);
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
            s->one_shot = 1;
            created = 1;
            fprintf(stderr, "PTY spawned %s (run, one-shot)\n", s->session_id);
        } else {
            if (!is_valid_uuid(sid, sid_len)) { free(cmd); return send_error(e, NULL, 0, bid, bid_len, "INVALID_SESSION_ID", "sessionId must be a UUID"); }
            s = find_session(e, sid, sid_len);
            if (!s) { free(cmd); return send_error(e, sid, sid_len, bid, bid_len, "SESSION_NOT_FOUND", "no session for sessionId"); }
            if (s->state == SESS_RUNNING) { free(cmd); return send_error(e, sid, sid_len, bid, bid_len, "SESSION_BUSY", "session already running a step"); }
            fprintf(stderr, "PTY resumed %s (run, state=%d)\n", s->session_id, s->state);
        }

        // Helper: on a fatal error after the new session was spawned, free
        // the slot so it doesn't leak. No-op for resumed sessions and for
        // already-closed slots (e.g. run_finish() already tore down a
        // one-shot on its way out).
        #define RUN_FAIL_CLEANUP() do { \
            if (created && s->active) { bridge_pty_close(&s->pty); s->active = 0; s->state = SESS_IDLE; } \
        } while (0)

        // Update opaque echo label from this RUN. Validated charset (same as
        // blockId) so it's safe to interpolate raw with %s. Absent ⇒ keep the
        // existing value; explicit "" ⇒ clear.
        const char *utid = NULL; size_t utid_len = 0;
        if (json_get_str(msg, msg_len, "todoId", &utid, &utid_len)) {
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
        long timeout_ms_raw = 0;
        json_get_long(msg, msg_len, "timeoutMs", &timeout_ms_raw);
        int64_t timeout_ms = (int64_t)timeout_ms_raw;
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
            send_step_done(e, s, /*has_code=*/0, 0, /*timedOut=*/0);
            run_finish(s);
            RUN_FAIL_CLEANUP();
            return 0;
        }
        // Stamp AFTER write_all returns: the bridge is single-threaded so the
        // probe couldn't have run during the write — only post-write ldisc
        // drain (≤4KB) needs the grace window.
        s->last_input_ms = monotonic_ms();
        free(wrapped);
        #undef RUN_FAIL_CLEANUP

    } else if (IS("input")) {
        // Forward raw stdin bytes — used to resume a paused RUN. The bridge
        // doesn't track which RUN consumes the bytes; the PTY/kernel/shell do.
        // Optional `requestId` is echoed via ACK on success or ERROR on failure
        // so the caller can correlate (e.g. "session already died").
        const char *rid = NULL; size_t rid_len = 0;
        int has_rid = json_get_str(msg, msg_len, "requestId", &rid, &rid_len)
                      && rid_len > 0 && is_valid_id(rid, rid_len);

        const char *sid = NULL; size_t sid_len = 0;
        if (!json_get_str(msg, msg_len, "sessionId", &sid, &sid_len))
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
        if (!json_get_str(msg, msg_len, "data", &b64, &b64_len))
            return has_rid ? send_req_error(e, sid, sid_len, rid, rid_len, "MISSING_DATA", "input requires data")
                           : send_error(e, sid, sid_len, NULL, 0, "MISSING_DATA", "input requires data");
        if (b64_len / 4 * 3 > BUF_SIZE)
            return has_rid ? send_req_error(e, sid, sid_len, rid, rid_len, "INPUT_TOO_LARGE", "input exceeds 4096 bytes")
                           : send_error(e, sid, sid_len, NULL, 0, "INPUT_TOO_LARGE", "input exceeds 4096 bytes");

        char decoded[BUF_SIZE + 4];
        size_t dec_len = b64_decode(b64, b64_len, decoded, sizeof(decoded));
        if (dec_len == 0 && b64_len > 0)
            return has_rid ? send_req_error(e, sid, sid_len, rid, rid_len, "INVALID_BASE64", "data is not valid base64")
                           : send_error(e, sid, sid_len, NULL, 0, "INVALID_BASE64", "data is not valid base64");

        if (bridge_pty_write_all(&s->pty, decoded, dec_len) != 0) {
            fprintf(stderr, "PTY write error\n");
            return has_rid ? send_req_error(e, sid, sid_len, rid, rid_len, "PTY_WRITE_FAILED", "PTY write failed; session may have died")
                           : 0;
        }
        s->last_active_ms = monotonic_ms();
        // Stamp AFTER write_all (see RUN handler comment above).
        s->last_input_ms = s->last_active_ms;
        // Input consumes the prompt: process leaves n_tty_read on the next
        // tick anyway, but reset the counter eagerly to avoid a stale tick
        // re-confirming on the same blocked-read.
        s->pause_consec_ticks = 0;

        if (has_rid) send_ack(e, rid, rid_len);

    } else if (IS("tool_catalog")) {
        // Server pushed the shell-command catalog; scan and reply.
        const char *entries = NULL; size_t entries_len = 0;
        if (!json_get_str(msg, msg_len, "entries", &entries, &entries_len)) return 0;

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
        bridge_scan_stats_t stats;
        int n = bridge_scan_tools(buf, w, out, MAX_MSG, &stats);
        if (n > 0) {
            send_json(e, out, (size_t)n);
            fprintf(stderr, "✓ Probed CLI tools: %d installed, %d authenticated\n",
                    stats.installed, stats.authenticated);
        } else {
            fprintf(stderr, "CLI tool probe failed (overflow or empty)\n");
        }
        free(out);
        free(buf);
    }

    #undef IS
    return 0;
}

// ── Main loop ───────────────────────────────────────────────────────────────

// Per-tick session servicing: reap, deadline, pause-probe, PTY drain. PTY
// master fds are non-blocking (set by bridge_pty_spawn), so reads here
// return 0 immediately when no data is available. Idle sessions live
// forever — slot pressure is handled lazily via LRU eviction on the next
// RUN (see evict_lru_idle()).
static void service_sessions(edge_t *e) {
    int64_t now = monotonic_ms();

    // Reap exited shells; if a step was in flight, surface STEP_DONE first
    // so the backend's pending RUN promise settles cleanly.
    for (int i = 0; i < g_max_sessions; i++) {
        session_t *s = &e->sessions[i];
        if (!s->active) continue;
        int code;
        if (bridge_pty_reap(&s->pty, &code)) {
            if (s->state == SESS_RUNNING) {
                if (s->tail_len > 0) {
                    send_output_bytes(e, s, s->tail_buf, s->tail_len);
                    s->tail_len = 0;
                }
                send_step_done(e, s, /*has_code=*/1, code, /*timedOut=*/0);
                // Shell already exited — outer block owns the close. Clear
                // one_shot so run_finish doesn't try to SIGKILL/close again.
                s->one_shot = 0;
                run_finish(s);
            }
            send_exit(e, s, code);
            bridge_pty_close(&s->pty);
            s->active = 0;
        }
    }

    // Per-step deadline. Settle the RUN; for persistent sessions the shell
    // is left alive (agent can retry on the same sessionId). One-shot
    // sessions are torn down by run_finish() since the agent never owned
    // the id and has no way to address them.
    for (int i = 0; i < g_max_sessions; i++) {
        session_t *s = &e->sessions[i];
        if (!s->active || s->state != SESS_RUNNING || s->deadline_ms == 0) continue;
        if (now < s->deadline_ms) continue;
        if (s->tail_len > 0) {
            send_output_bytes(e, s, s->tail_buf, s->tail_len);
            s->tail_len = 0;
        }
        send_step_done(e, s, /*has_code=*/0, 0, /*timedOut=*/1);
        run_finish(s);
    }

    // Pause detection: poll the wchan probe at PAUSE_POLL_MS cadence; emit
    // STEP_PAUSED once `blocked` has been observed PAUSE_CONFIRM_TICKS times
    // in a row. A single non-blocked tick (e.g. process resumed, or it was a
    // transient pipe_read between bytes) resets the counter.
    for (int i = 0; i < g_max_sessions; i++) {
        session_t *s = &e->sessions[i];
        if (!s->active || s->state != SESS_RUNNING) continue;
        if (now - s->last_pause_poll_ms < PAUSE_POLL_MS) continue;
        s->last_pause_poll_ms = now;

        // Grace window after our last write to the PTY: large single-line
        // inputs (e.g. multi-MB doc_write base64) take seconds to drain
        // through line discipline, during which the slave shell legitimately
        // sits in read(/dev/pts/*) — but waiting for *us*, not for user
        // stdin. Skip the probe entirely for INPUT_GRACE_MS after each write.
        if (now - s->last_input_ms < INPUT_GRACE_MS) { s->pause_consec_ticks = 0; continue; }

        long fg = 0; int pwd = 0;
        int blocked = bridge_pty_probe_blocked(&s->pty, /*echo_baseline=*/0, &fg, &pwd);
        if (!blocked) { s->pause_consec_ticks = 0; continue; }
        if (++s->pause_consec_ticks != PAUSE_CONFIRM_TICKS) continue;

        if (s->tail_len > 0) {
            send_output_bytes(e, s, s->tail_buf, s->tail_len);
            s->tail_len = 0;
        }
        // Promote one-shot to persistent: the agent now has the minted
        // sessionId and may resume by sending INPUT (or another RUN against
        // this session). STEP_DONE must not tear the PTY down under it.
        s->one_shot = 0;
        send_step_paused(e, s, fg, pwd);
        fprintf(stderr, "RUN paused (waiting for stdin): %s fg=%ld pwd=%d\n",
                s->run_block_id, fg, pwd);
    }

    // Drain PTY masters (non-blocking; returns 0 on EAGAIN).
    for (int i = 0; i < g_max_sessions; i++) {
        session_t *s = &e->sessions[i];
        if (s->active) forward_pty_output(e, s);
    }
}

static void on_ws_msg(uint8_t op, const uint8_t *data, size_t len, void *ctx) {
    edge_t *e = ctx;
    if (op != WS_OP_BINARY) return;
    long n = noise_ws_recv(&e->noise, data, len, e->msg_buf, sizeof(e->msg_buf));
    if (n < 0) {
        fail(e, e->noise.handshake_done
                ? "noise decrypt failed (corrupt frame, replay, or out-of-order)"
                : "noise handshake failed (wrong --server-pubkey or incompatible build)");
        return;
    }
    if (n == 0) {
        // Handshake just completed → send auth. Identity is deferred (see edge_t).
        char auth[1024]; size_t u = 0;
        if (json_emit_raw(auth, sizeof auth, &u, "{", 1) < 0 ||
            jfield_str(auth, sizeof auth, &u, "type", "auth", -1, 0) < 0 ||
            jfield_str(auth, sizeof auth, &u, "deviceId", e->device_id, -1, 1) < 0 ||
            jfield_str(auth, sizeof auth, &u, "secret", e->device_secret, -1, 1) < 0 ||
            json_emit_raw(auth, sizeof auth, &u, "}", 1) < 0) { fail(e, "failed to build auth frame"); return; }
        if (send_json(e, auth, u) != 0) { fail(e, "failed to send auth frame"); return; }
        e->auth_sent_ms = monotonic_ms();
        return;
    }
    if (getenv("BRIDGE_DEBUG_WIRE"))
        fprintf(stderr, "← recv (%ld) %.*s\n", n, (int)(n > 512 ? 512 : n), (const char *)e->msg_buf);
    handle_command(e, (const char *)e->msg_buf, (size_t)n);
}

static int run(edge_t *e, const char *device_id, const char *device_secret,
               const char *host, uint16_t port, const char *path,
               const uint8_t pubkey[32]) {
    e->device_id = device_id;
    e->device_secret = device_secret;
    if (noise_ws_init(&e->noise, pubkey) != 0) {
        fail(e, "failed to initialize noise (bad server pubkey?)");
        return -1;
    }
    // ws rx capacity: plaintext MAX_MSG + Noise auth tag (16) + WS header slack.
    if (ws_connect(&e->ws, host, port, path, MAX_MSG + NOISE_TAG_LEN + 16, 10000) != 0) {
        fail(e, "%s", e->ws.err);
        return -1;
    }
    if (noise_ws_start(&e->noise, &e->ws) != 0) {
        fail(e, "failed to start noise handshake");
        ws_close(&e->ws);
        return -1;
    }

    while (!e->done) {
        struct pollfd pfd = { .fd = e->ws.fd, .events = POLLIN | (ws_want_write(&e->ws) ? POLLOUT : 0) };
        int pr = poll(&pfd, 1, 50);
#ifdef _WIN32
        if (pr < 0) { fail(e, "poll failed (WSA %d)", WSAGetLastError()); break; }
#else
        if (pr < 0) {
            if (errno == EINTR) continue;
            fail(e, "poll failed (errno %d)", errno);
            break;
        }
#endif
        if (pr > 0) {
            if (pfd.revents & (POLLERR | POLLNVAL)) {
                fail(e, "socket error (revents=0x%x)", pfd.revents);
                break;
            }
            if (pfd.revents & (POLLIN | POLLHUP)) {
                int rc = ws_io_in(&e->ws, on_ws_msg, e);
                // Surface CLOSE frame metadata regardless of rc — a clean
                // server-initiated close arrives via ws_io_in returning 0
                // with ws.closed=1; transport errors return -1.
                if (e->ws.have_close) {
                    e->got_close_frame = 1;
                    e->close_code = e->ws.close_code;
                    snprintf(e->close_reason, sizeof e->close_reason, "%s", e->ws.close_reason);
                }
                if (rc < 0 || e->ws.closed) {
                    fail(e, "%s", e->ws.err[0] ? e->ws.err
                                : (e->identity_sent ? "peer closed connection (server died or network dropped)"
                                                    : "peer closed connection before authentication"));
                    // Best-effort flush of our queued CLOSE reply before we tear down.
                    if (ws_want_write(&e->ws)) (void)ws_io_out(&e->ws);
                    break;
                }
            }
            if (pfd.revents & POLLOUT) {
                if (ws_io_out(&e->ws) < 0) { fail(e, "%s", e->ws.err); break; }
            }
        }
        // Deferred identity send — gives the backend's async validateDevice()
        // time to settle before the second frame lands on the post-auth handler.
        if (e->noise.handshake_done && !e->identity_sent &&
            e->auth_sent_ms != 0 && monotonic_ms() - e->auth_sent_ms >= 100) {
            char id[1024];
            int il = bridge_identity_json(id, sizeof id, 0);
            if (il <= 0 || send_json(e, id, (size_t)il) != 0) { fail(e, "failed to send identity frame"); break; }
            e->identity_sent = 1;
            fprintf(stderr, "✓ Authenticated\n");
        }
        service_sessions(e);
        // Drain any send queue produced by service_sessions / handle_command.
        if (ws_want_write(&e->ws) && ws_io_out(&e->ws) < 0) { fail(e, "%s", e->ws.err); break; }
    }
    ws_close(&e->ws);
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

// Resolve concurrent-session cap from BRIDGE_MAX_SESSIONS, clamped to a
// sane range. Intentionally undocumented in --help; tune for heavy users.
static int resolve_max_sessions(void) {
    const char *s = getenv("BRIDGE_MAX_SESSIONS");
    if (!s || !*s) return DEFAULT_MAX_SESSIONS;
    int v = atoi(s);
    if (v < 1) v = 1;
    if (v > 4096) v = 4096;  // hard upper bound — fd/RAM ceiling well before this
    return v;
}

// Best-effort: raise RLIMIT_NOFILE's soft limit toward `want` (capped at the
// hard limit). Any process is allowed to do this without privileges; only
// raising the hard limit needs CAP_SYS_RESOURCE. Failure is logged but not
// fatal — the existing limit may already be sufficient.
static void bump_fd_limit(int want) {
#ifndef _WIN32
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return;
    rlim_t target = (rlim_t)want;
    if (rl.rlim_cur >= target) return;
    rlim_t cap = rl.rlim_max == RLIM_INFINITY ? target : rl.rlim_max;
    rl.rlim_cur = target < cap ? target : cap;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
        fprintf(stderr, "warn: could not raise RLIMIT_NOFILE to %d (have %lu): %s\n",
                want, (unsigned long)rl.rlim_cur, strerror(errno));
#else
    (void)want;
#endif
}

int main(int argc, char **argv) {
    // If a new binary was staged next to us (by a prior `exec` update command),
    // swap it in before we do anything else. See update.h.
    bridge_update_swap_on_start(argv[0]);

    // Subcommand dispatch (must come before option parsing so `bridge login -h`
    // shows the login-specific usage).
    if (argc >= 2 && strcmp(argv[1], "login") == 0) {
        int rc = cmd_login(argc - 1, argv + 1);
        if (rc == CMD_RC_HELP) return 0;   // help printed → done, don't start daemon
        if (rc != 0) return rc;
        // Fall through into the daemon: user is now logged in, no need to re-run.
        argc = 1;
    }
    if (argc >= 2 && strcmp(argv[1], "logout") == 0) {
        return cmd_logout(argc - 1, argv + 1);
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
        else cli_parse_error("todoforai-bridge", USAGE_MAIN, argc, argv, &opt, c);
    }

    // Load saved device credentials from `bridge login`
    login_credentials_t saved_creds;
    memset(&saved_creds, 0, sizeof(saved_creds));
    (void)login_load_credentials(&saved_creds);

    // No creds yet → run the login flow inline. The user just typed
    // `todoforai-bridge`, so do the obvious thing instead of asking them
    // to re-run with `login`. After successful login we fall through and
    // start the daemon. Sandbox/systemd setups always pre-provision via
    // `login --token`, so they never hit this path.
    if (!saved_creds.device_id[0] || !saved_creds.device_secret[0]) {
        fprintf(stderr, "No device credentials found. Starting login...\n\n");
        // Forward --host / --server-pubkey so login targets the same backend.
        // --port is intentionally not forwarded: it's BRIDGE_PORT (HTTP/WS) here
        // vs NOISE_BACKEND_PORT for login — different transports.
        int rc = bridge_login_run(NULL, NULL, host, NULL, pubkey_hex);
        if (rc != 0) return rc;
        if (login_load_credentials(&saved_creds) < 0
            || !saved_creds.device_id[0] || !saved_creds.device_secret[0]) {
            fprintf(stderr, "error: login completed but no credentials saved.\n");
            return 1;
        }
    }

    if (!host) host = getenv("NOISE_BACKEND_HOST");
    if (!host && saved_creds.backend_host[0]) host = saved_creds.backend_host;
    if (!host) host = DEFAULT_HOST;

    if (!port_s) port_s = getenv("BRIDGE_PORT"); // bridge HTTP/WS port (not Noise)
    uint16_t port = DEFAULT_PORT;
    if (port_s) {
        int p = atoi(port_s);
        if (p > 0 && p <= 65535) port = (uint16_t)p;
    } else if (strcmp(host, "localhost") == 0 || strcmp(host, "127.0.0.1") == 0
            || strcmp(host, "::1") == 0       || strcmp(host, "[::1]") == 0) {
        port = 4000; // dev default: bun listens directly (no nginx)
    }

    if (!pubkey_hex) pubkey_hex = getenv("NOISE_BACKEND_PUBKEY");
    if (!pubkey_hex) pubkey_hex = DEFAULT_SERVER_PUBKEY_HEX;

    uint8_t server_pubkey[32];
    if (parse_pubkey_hex(pubkey_hex, server_pubkey) != 0) {
        fprintf(stderr, "invalid server pubkey (need 64 hex chars)\n");
        return 1;
    }

    // Show 8-char device id prefix so the trailing "..." reads as "connecting…"
    // rather than "id truncated". Full id is in ~/.config/todoforai/credentials.json.
    fprintf(stderr, "Connecting to %s:%u (device: %.8s…) ...\n",
            host, (unsigned)port, saved_creds.device_id);

    g_max_sessions = resolve_max_sessions();
    // Each session needs a master fd + a few transient pipes in the child
    // spawn path. Add headroom for the bridge's own fds (ws, stdio, etc.).
    bump_fd_limit(g_max_sessions + 64);

    edge_t *e = calloc(1, sizeof(*e));
    if (!e) return 1;
    e->sessions = calloc((size_t)g_max_sessions, sizeof(*e->sessions));
    if (!e->sessions) { free(e); return 1; }

    int rc = run(e, saved_creds.device_id, saved_creds.device_secret,
                 host, port, DEFAULT_PATH, server_pubkey);

    for (int i = 0; i < g_max_sessions; i++) {
        if (e->sessions[i].active) bridge_pty_close(&e->sessions[i].pty);
    }

    if (rc != 0) {
        // Server-sent close frames carry the most specific reason — prefer them.
        // Otherwise fall back to err_msg, which fail() guarantees is populated.
        if (e->got_close_frame) {
            const char *reason = e->close_reason[0] ? e->close_reason : "(no reason)";
            const char *hint = "";
            switch (e->close_code) {
                case 4401: hint = "\nRe-run `todoforai-bridge login` (device removed or secret rotated)."; break;
                case 4408: hint = "\nServer didn't receive auth in time — check network/firewall."; break;
                case 4001: hint = "\nWrong --server-pubkey or incompatible build. Try `todoforai-bridge --version`."; break;
                case 4003: break;  // protocol error, reason is self-explanatory
                default:   break;
            }
            fprintf(stderr, "Disconnected by server (code=%u): %s.%s\n",
                    e->close_code, reason, hint);
        } else {
            fprintf(stderr, "Connection failed: %s.\n",
                    e->err_msg[0] ? e->err_msg : "(no diagnostic — please report)");
            // Connect-time failures: hint at common misconfig.
            if (!e->noise.handshake_done)
                fprintf(stderr,
                    "  --port is the HTTP/WS port (4000 dev, 80/443 prod), NOT the Noise-TCP\n"
                    "  port (14100/4100) used by `login`/`enroll`. Or re-run `todoforai-bridge login`.\n");
        }
    }
    free(e->sessions);
    free(e);
    return rc == 0 ? 0 : 1;
}
