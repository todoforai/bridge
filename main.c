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
//   (unless STEP_AWAITING_INPUT upgraded it to a persistent session).
//     → {"type":"identity","data":{...}}
//     ← {"type":"run","sessionId":"uuid"?,"blockId":"...","cmdB64":"...","cwd":"...","timeoutMs":N}
//     → {"type":"run_started","sessionId":"uuid","blockId":"...","shellPid":N,"created":bool,"cwd":"..."}
//     → {"type":"output","sessionId":"uuid","blockId":"...","data":"base64"}
//     → {"type":"step_awaiting_input","sessionId":"uuid","blockId":"...","shellPid":N,"passwordPrompt":bool}
//     → {"type":"step_done","sessionId":"uuid","blockId":"...","shellPid":N,"exitCode":N|null,"timedOut":bool}
//     ← {"type":"input","sessionId":"uuid","data":"base64","requestId":"..."}   // resumes a step waiting on stdin
//     → {"type":"ack","requestId":"..."}                            // success reply for input
//     → {"type":"exit","sessionId":"uuid","blockId":"...","code":N}
//     ↔ {"type":"error","sessionId":"uuid","blockId":"...","code":"ERR","message":"..."}
//   Payload-wrapped (generic function dispatch, shared with agent↔edge):
//     ← {"type":"FUNCTION_CALL_REQUEST_AGENT","payload":{"requestId","functionName","args",...}}
//     → {"type":"FUNCTION_CALL_RESULT_AGENT","payload":{"requestId","success","result"|"error",...}}
//   Bridge implements:
//     • `scan_tools`     — args.entries = "<key>\t<b64_versionCmd>\t<b64_statusCmd>\n…";
//                          result = installed-tools dict.
//     • `write_file_b64` — args = {path, dataB64, offset?, truncate?};
//                          result = {bytesWritten, totalSize}.

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
#  include <direct.h>     // _mkdir
#  include <io.h>         // _open/_write/_lseeki64/_chsize_s
#  include <fcntl.h>      // _O_WRONLY/_O_CREAT/_O_BINARY/_O_APPEND
#  include <sys/stat.h>   // _S_IREAD/_S_IWRITE
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
#  include <fcntl.h>
#  include <poll.h>
#  include <pwd.h>          // getpwnam/getpwuid for ~user expansion
#  include <sys/file.h>     // flock
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

// Expand a leading `~` / `~/rest` / `~user/rest` to an absolute path, matching
// what /bin/sh would do for shell commands (write_file_b64 bypasses the shell,
// so it must expand the tilde itself). Returns a malloc'd string the caller
// frees, or NULL when no expansion applies (path used as-is).
static char *bridge_expand_tilde(const char *p) {
    if (!p || p[0] != '~') return NULL;
    const char *rest = p + 1;                 // after '~'
    const char *home = NULL;
#ifdef _WIN32
    if (*rest != '\0' && *rest != '/' && *rest != '\\') return NULL;  // no ~user on Windows
    home = getenv("USERPROFILE");
    if (!home || !*home) return NULL;
#else
    char namebuf[256];
    if (*rest == '\0' || *rest == '/') {       // ~ or ~/...
        home = getenv("HOME");
        if (!home || !*home) {
            struct passwd *pw = getpwuid(getuid());
            home = pw ? pw->pw_dir : NULL;
        }
    } else {                                   // ~user or ~user/...
        const char *slash = strchr(rest, '/');
        size_t nlen = slash ? (size_t)(slash - rest) : strlen(rest);
        if (nlen == 0 || nlen >= sizeof(namebuf)) return NULL;
        memcpy(namebuf, rest, nlen);
        namebuf[nlen] = '\0';
        struct passwd *pw = getpwnam(namebuf);
        if (!pw) return NULL;
        home = pw->pw_dir;
        rest = slash ? slash : rest + nlen;    // remainder starts at '/' (or empty)
    }
    if (!home || !*home) return NULL;
#endif
    size_t hlen = strlen(home), rlen = strlen(rest);
    char *out = malloc(hlen + rlen + 1);
    if (!out) return NULL;
    memcpy(out, home, hlen);
    memcpy(out + hlen, rest, rlen + 1);
    return out;
}

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


// ── Session ─────────────────────────────────────────────────────────────────

// Per-step sentinel envelope (bridge owns this; backend never sees raw bytes).
//   Wrapper:    { <user-cmd>\n}; __RC=$?; printf '\n<sentinel>:%d\n' "$__RC"\n
//   Sentinel:   __BRIDGE_STEP_<32 hex>__   → 16 + 32 + 2 = 50 chars; pad to 64.
#define SENTINEL_CAP   64
// Upper bound: previous read may have left up to (sentinel_len - 1) bytes in
// the tail; the next read appends ≤ BUF_SIZE bytes. SENTINEL_CAP overshoots
// `sentinel_len - 1` and rounds the buffer to a power of two.
#define TAIL_CAP       (BUF_SIZE + SENTINEL_CAP)

// ── Output policy (mirrors packages/shared-fbe/src/outputLimits.ts) ──
// The bridge owns ALL shell-output management for the RUN path now: it streams
// the head live, goes silent once the head fills, rolls a tail, and emits a
// truncation notice + tail at STEP_DONE. The backend is a dumb relay that just
// concatenates OUTPUT bytes. (size_t)-1 means "no limit" (raw / full head).
#define OB_NOLIMIT      ((size_t)-1)
#define OB_STREAM_FIRST 10000              // chars kept/streamed from the start
#define OB_STREAM_LAST  10000              // chars kept from the end (tail)
#define OB_RUN_CAP      (256 * 1024)       // absolute ceiling (full mode)
#define OB_LINE_LEN     300                // per-line width cap
// Tail buffer: holds the rolling last OB_STREAM_LAST bytes plus one full PTY
// read of slack so a single append never overflows before we trim.
#define OB_TAIL_CAP     (OB_STREAM_LAST + BUF_SIZE)

typedef struct {
    size_t head_limit;   // min(firstLimit, hardCap); stream live until reached
    size_t last_limit;   // min(lastLimit, hardCap - head_limit); rolling tail
    size_t line_limit;   // per-line width cap (OB_NOLIMIT = full-width)
    size_t head_len;     // bytes already streamed into the head
    size_t total_len;    // total RUN output bytes seen
    int    truncated;    // head filled and more arrived
    int    notice_sent;  // truncation notice already emitted
    // Streaming line-width state (head phase): suppress bytes past line_limit on
    // the current line; emit " ...[+N chars]" when the newline arrives.
    size_t col;          // column within the current line (head stream)
    size_t line_dropped; // bytes dropped on the current (over-long) line
    // Rolling tail of the last `last_limit` bytes (raw, not line-capped yet).
    uint8_t tail[OB_TAIL_CAP];
    size_t  tail_len;
} out_policy_t;


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
    // if the run hits STEP_AWAITING_INPUT — at that point the agent has the
    // minted sessionId and the session becomes persistent for resume.
    int one_shot;

    // Working dir the PTY was spawned in (the explicit RUN `cwd` or the
    // <tmpdir>/todoforai default from resolve_default_cwd). Echoed in
    // RUN_STARTED so the backend/UI can show the real cwd — the bridge is
    // the only side that knows the resolved default (it depends on remote
    // $TMPDIR). Set once at spawn; persistent sessions keep their dir.
    char cwd[1024];

    // Opaque echo label set from RunMessage.todoId. Bridge never interprets
    // it — just stashes it on the session and echoes it on every related
    // frame so the backend's OUTPUT/EXIT/ERROR routing is self-describing.
    char todo_id[BLOCK_ID_CAP + 1];
    size_t todo_id_len;

    // Agent settings id of the calling TODO. Exported as
    // TODOFORAI_AGENT_SETTINGS_ID in this PTY's wrapper env so a tfa-* child
    // inherits the parent agent. Cleared when RUN sends an empty value.
    char agent_settings_id[BLOCK_ID_CAP + 1];
    size_t agent_settings_id_len;

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
    // Rolling buffer for the trailing sentinel_len bytes (sentinel may span
    // read() chunks).
    uint8_t tail_buf[TAIL_CAP];
    size_t  tail_len;
    // LRU key for idle-session eviction. SESS_RUNNING is never evicted.
    int64_t last_active_ms;
    // Awaiting-input probe: poll wchan every PAUSE_POLL_MS, fire after
    // PAUSE_CONFIRM_TICKS consecutive `blocked` ticks. Resumption resets implicitly.
    int64_t last_pause_poll_ms;
    int     pause_consec_ticks;
    // Stamp after bridge_pty_write_all; probe waits INPUT_GRACE_MS past it to
    // avoid false-pause during the trailing line-discipline drain.
    int64_t last_input_ms;

    // Per-RUN output policy (head/tail cut + line cap). Reset on each RUN.
    out_policy_t ob;
} session_t;

// 2 ticks × 250 ms ⇒ ~250-500 ms latency, FP rate ~1-2%.
#define PAUSE_POLL_MS        250
#define PAUSE_CONFIRM_TICKS  2
// Grace after write covers the ldisc drain (~tens of ms on Linux n_tty);
// stays well below PAUSE_POLL_MS*PAUSE_CONFIRM_TICKS so prompt latency is unaffected.
#define INPUT_GRACE_MS       500

typedef struct {
    ws_t ws;
    noise_ws_t noise;
    const char *device_id;
    const char *device_secret;
    const char *user_email;  // for the auth banner; points into main()'s saved_creds
    int done;
    int rc;
    // Defer identity until auth round-trip settles: backend awaits
    // validateDevice() async, so a TCP-coalesced 2nd frame is rejected.
    int identity_sent;
    int64_t auth_sent_ms;

    // Bearer (dst_… 64 hex) from backend post-auth. Exported as
    // TODOFORAI_API_TOKEN to PTY children (tfa-* auth without the user
    // shipping a real API key). Refresh = reconnect.
    char subagent_token[80];

    // Bridge's HTTP API URL, exported as TODOFORAI_API_URL so child CLIs
    // route to the SAME backend that minted the token.
    char api_url[320];

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

// Clear per-connection state between reconnect attempts. e->sessions is NOT
// touched — PTY processes survive across reconnects. run() always calls
// ws_close() + noise_ws_wipe() before returning, so the memsets here clear
// already-released structs (no leak).
static void reset_connection_state(edge_t *e) {
    memset(&e->ws, 0, sizeof(e->ws));
    memset(&e->noise, 0, sizeof(e->noise));
    e->done = 0; e->rc = 0;
    e->identity_sent = 0; e->auth_sent_ms = 0;
    e->got_close_frame = 0; e->close_code = 0;
    e->close_reason[0] = '\0'; e->err_msg[0] = '\0';
    // Token is reissued by the backend on every reconnect; drop the stale one.
    e->subagent_token[0] = '\0';
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


// Default cwd when RUN omits `cwd`: <tmpdir>/todoforai. Mirrors
// edge/bun/src/shell.ts so both transports behave identically when no
// workspace is configured (instead of inheriting wherever the daemon was
// launched). mkdir errors are ignored — if the dir genuinely can't be used,
// the child's chdir fails and surfaces as SPAWN_FAILED.
static const char *resolve_default_cwd(void) {
    static char path[512];
    if (path[0]) return path;
#ifdef _WIN32
    char tmp[MAX_PATH];
    DWORD n = GetTempPathA(sizeof(tmp), tmp);
    if (n == 0 || n >= sizeof(tmp)) { strcpy(path, "C:\\"); return path; }
    snprintf(path, sizeof(path), "%s%stodoforai", tmp, tmp[n-1] == '\\' ? "" : "\\");
    _mkdir(path);
#else
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir || !*tmpdir) tmpdir = "/tmp";
    snprintf(path, sizeof(path), "%s/todoforai", tmpdir);
    mkdir(path, 0700);
#endif
    return path;
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

// Emit a FUNCTION_CALL_RESULT_AGENT frame. `result_obj` is a pre-built JSON
// value (object/array/string/number/bool/null) — inlined verbatim into the
// `result` field. Payload-wrapped to match the agent↔edge function-call
// envelope (the only payload-wrapped frame the bridge produces).
static int send_function_call_result(edge_t *e,
                                     const char *rid, size_t rid_len,
                                     const char *aid, size_t aid_len,
                                     const char *eid, size_t eid_len,
                                     const char *result_obj, size_t result_len) {
    // Envelope ≈ 80 bytes of literal JSON + each ID up to 6× expansion via
    // \uXXXX (control bytes). IDs come unvalidated from agent-controlled
    // payload so be generous.
    size_t cap = result_len + (rid_len + aid_len + eid_len) * 6 + 128;
    char *buf = malloc(cap);
    if (!buf) return -1;
    size_t u = 0;
    int ok =
        json_emit_raw(buf, cap, &u, "{", 1) == 0 &&
        jfield_str(buf, cap, &u, "type", "FUNCTION_CALL_RESULT_AGENT", -1, 0) == 0 &&
        json_emit_raw(buf, cap, &u, ",\"payload\":{", 12) == 0 &&
        jfield_str(buf, cap, &u, "requestId", rid, (long)rid_len, 0) == 0 &&
        (aid_len > 0 ? jfield_str(buf, cap, &u, "agentId", aid, (long)aid_len, 1) : 0) == 0 &&
        (eid_len > 0 ? jfield_str(buf, cap, &u, "edgeId", eid, (long)eid_len, 1) : 0) == 0 &&
        json_emit_raw(buf, cap, &u, ",\"success\":true,\"result\":", 25) == 0 &&
        json_emit_raw(buf, cap, &u, result_obj, result_len) == 0 &&
        json_emit_raw(buf, cap, &u, "}}", 2) == 0;
    if (ok) send_json(e, buf, u);
    free(buf);
    return ok ? 0 : -1;
}

static int send_function_call_error(edge_t *e,
                                    const char *rid, size_t rid_len,
                                    const char *aid, size_t aid_len,
                                    const char *eid, size_t eid_len,
                                    const char *message) {
    char buf[1024]; size_t u = 0;
    int ok =
        json_emit_raw(buf, sizeof buf, &u, "{", 1) == 0 &&
        jfield_str(buf, sizeof buf, &u, "type", "FUNCTION_CALL_RESULT_AGENT", -1, 0) == 0 &&
        json_emit_raw(buf, sizeof buf, &u, ",\"payload\":{", 12) == 0 &&
        jfield_str(buf, sizeof buf, &u, "requestId", rid, (long)rid_len, 0) == 0 &&
        (aid_len > 0 ? jfield_str(buf, sizeof buf, &u, "agentId", aid, (long)aid_len, 1) : 0) == 0 &&
        (eid_len > 0 ? jfield_str(buf, sizeof buf, &u, "edgeId", eid, (long)eid_len, 1) : 0) == 0 &&
        json_emit_raw(buf, sizeof buf, &u, ",\"success\":false,", 17) == 0 &&
        jfield_str(buf, sizeof buf, &u, "error", message, -1, 0) == 0 &&
        json_emit_raw(buf, sizeof buf, &u, "}}", 2) == 0;
    if (ok) send_json(e, buf, u);
    fprintf(stderr, "function_call_error: %s\n", message);
    return ok ? 0 : -1;
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
    // cwd is up to 1023 bytes and JSON-escaping can expand control bytes 6x;
    // size for the worst case so a valid path never drops the frame (losing
    // RUN_STARTED would drop the live pid/cwd the UI needs for cancel/stdin).
    char buf[8192]; size_t u = 0;
    char pid_buf[24]; snprintf(pid_buf, sizeof pid_buf, "%ld", SHELL_PID(s));
    if (json_emit_raw(buf, sizeof buf, &u, "{", 1) < 0 ||
        jfield_str(buf, sizeof buf, &u, "type", "run_started", -1, 0) < 0 ||
        jfield_str(buf, sizeof buf, &u, "sessionId", s->session_id, -1, 1) < 0 ||
        emit_todo_id(buf, sizeof buf, &u, s) < 0 ||
        jfield_str(buf, sizeof buf, &u, "blockId", s->run_block_id, (long)s->run_block_id_len, 1) < 0 ||
        jfield_raw(buf, sizeof buf, &u, "shellPid", pid_buf, 1) < 0 ||
        jfield_raw(buf, sizeof buf, &u, "created", created ? "true" : "false", 1) < 0 ||
        jfield_str(buf, sizeof buf, &u, "cwd", s->cwd, -1, 1) < 0 ||
        json_emit_raw(buf, sizeof buf, &u, "}", 1) < 0) {
        fprintf(stderr, "run_started serialization overflow for %s — frame dropped\n", s->session_id);
        return;
    }
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
        jfield_raw(buf, sizeof buf, &u, "truncated", s->ob.truncated ? "true" : "false", 1) < 0 ||
        json_emit_raw(buf, sizeof buf, &u, "}", 1) < 0) return;
    send_json(e, buf, u);
}

// Bridge → server: step's fg process is blocked in a tty read. RUN stays in
// flight; backend resolves the promise with awaitingInput:true so the agent
// can resume via INPUT on the same sessionId. `passwordPrompt` ⇔ ECHO off.
static void send_step_awaiting_input(edge_t *e, session_t *s, int password_prompt) {
    char buf[512]; size_t u = 0;
    char shell_pid_buf[24]; snprintf(shell_pid_buf, sizeof shell_pid_buf, "%ld", SHELL_PID(s));
    if (json_emit_raw(buf, sizeof buf, &u, "{", 1) < 0 ||
        jfield_str(buf, sizeof buf, &u, "type", "step_awaiting_input", -1, 0) < 0 ||
        jfield_str(buf, sizeof buf, &u, "sessionId", s->session_id, -1, 1) < 0 ||
        emit_todo_id(buf, sizeof buf, &u, s) < 0 ||
        jfield_str(buf, sizeof buf, &u, "blockId", s->run_block_id, (long)s->run_block_id_len, 1) < 0 ||
        jfield_raw(buf, sizeof buf, &u, "shellPid", shell_pid_buf, 1) < 0 ||
        jfield_raw(buf, sizeof buf, &u, "passwordPrompt", password_prompt ? "true" : "false", 1) < 0 ||
        jfield_raw(buf, sizeof buf, &u, "truncated", s->ob.truncated ? "true" : "false", 1) < 0 ||
        json_emit_raw(buf, sizeof buf, &u, "}", 1) < 0) return;
    send_json(e, buf, u);
}

// Reset per-step state. Trailing PTY bytes still emit OUTPUT (no blockId).
// One-shot sessions tear down here; promoted sessions (one_shot cleared in
// send_step_awaiting_input) survive.
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
        // SIGKILL (not "exit\n") to keep bridge_pty_close's waitpid bounded.
        // No EXIT frame: STEP_DONE already settled the promise.
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

// ── Output policy engine (RUN path) ─────────────────────────────────────────
// Streams the head live (line-capped), goes silent once the head fills, rolls
// the last `last_limit` bytes in a tail, and emits a truncation notice + tail
// at the end. Mirrors edge's OutputBuffer (edge/bun/src/shell.ts) so both
// transports cut identically. The backend just concatenates OUTPUT bytes.

// Resolve the RUN's `output` mode to concrete limits. Mirrors
// resolveOutputPolicy(): unknown/absent ⇒ "safe".
static void ob_resolve(out_policy_t *ob, const char *mode, size_t mode_len) {
    size_t first, last, cap, line;
#define OB_MODE_IS(str) (mode && mode_len == sizeof(str) - 1 && memcmp(mode, str, sizeof(str) - 1) == 0)
    if (OB_MODE_IS("wide")) {
        first = OB_STREAM_FIRST; last = OB_STREAM_LAST; cap = OB_STREAM_FIRST + OB_STREAM_LAST; line = OB_NOLIMIT;
    } else if (OB_MODE_IS("full")) {
        first = OB_NOLIMIT; last = 0; cap = OB_RUN_CAP; line = OB_LINE_LEN;
    } else if (OB_MODE_IS("raw")) {
        first = OB_NOLIMIT; last = 0; cap = OB_NOLIMIT; line = OB_NOLIMIT;
    } else { // safe (default)
        first = OB_STREAM_FIRST; last = OB_STREAM_LAST; cap = OB_STREAM_FIRST + OB_STREAM_LAST; line = OB_LINE_LEN;
    }
#undef OB_MODE_IS
    // head_limit = min(first, cap); last_limit = min(last, cap - head_limit).
    size_t head = (cap == OB_NOLIMIT) ? first
                : (first == OB_NOLIMIT) ? cap
                : (first < cap ? first : cap);
    size_t lastlim;
    if (cap == OB_NOLIMIT) lastlim = last;
    else { size_t room = (head >= cap) ? 0 : cap - head; lastlim = last < room ? last : room; }
    ob->head_limit = head; ob->last_limit = lastlim; ob->line_limit = line;
    ob->head_len = 0; ob->total_len = 0; ob->truncated = 0; ob->notice_sent = 0;
    ob->col = 0; ob->line_dropped = 0; ob->tail_len = 0;
}

// Clear counters/tail but keep the resolved limits (used at STEP_AWAITING_INPUT,
// mirroring edge's resetForInteraction so post-prompt output is a fresh delta).
static void ob_reset(out_policy_t *ob) {
    ob->head_len = 0; ob->total_len = 0; ob->truncated = 0; ob->notice_sent = 0;
    ob->col = 0; ob->line_dropped = 0; ob->tail_len = 0;
}

// Append to the rolling tail, keeping only the last `last_limit` bytes.
static void ob_tail_push(out_policy_t *ob, const uint8_t *d, size_t n) {
    size_t cap = ob->last_limit;
    if (cap == 0) return;
    if (cap > OB_TAIL_CAP) cap = OB_TAIL_CAP;  // defensive; last_limit ≤ OB_STREAM_LAST today
    if (n >= cap) { memcpy(ob->tail, d + (n - cap), cap); ob->tail_len = cap; return; }
    if (ob->tail_len + n > cap) {
        size_t drop = ob->tail_len + n - cap;
        memmove(ob->tail, ob->tail + drop, ob->tail_len - drop);
        ob->tail_len -= drop;
    }
    memcpy(ob->tail + ob->tail_len, d, n);
    ob->tail_len += n;
}

// Emit `n` bytes through the per-line width cap (col/line_dropped persist across
// calls so a line can span PTY reads). line_limit == OB_NOLIMIT ⇒ pass through.
static void ob_emit_capped(edge_t *e, session_t *s, const uint8_t *d, size_t n) {
    out_policy_t *ob = &s->ob;
    if (n == 0) return;
    if (ob->line_limit == OB_NOLIMIT) { send_output_bytes(e, s, d, n); return; }
    size_t cap = n * 2 + 64;
    uint8_t *out = malloc(cap);
    if (!out) { send_output_bytes(e, s, d, n); return; }  // degrade to uncapped
    size_t u = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = d[i];
        if (c == '\n') {
            if (ob->line_dropped > 0) {
                int m = snprintf((char *)out + u, cap - u, " ...[+%zu chars]", ob->line_dropped);
                if (m > 0 && (size_t)m < cap - u) u += (size_t)m;
                ob->line_dropped = 0;
            }
            out[u++] = '\n';
            ob->col = 0;
        } else if (ob->col < ob->line_limit) {
            out[u++] = c; ob->col++;
        } else {
            ob->line_dropped++;
        }
    }
    if (u > 0) send_output_bytes(e, s, out, u);
    free(out);
}

// Feed RUN output bytes: stream the head (line-capped), roll the rest into the
// tail. Drives s->ob; all RUN-path output goes through here.
static void ob_append(edge_t *e, session_t *s, const uint8_t *d, size_t n) {
    out_policy_t *ob = &s->ob;
    if (n == 0) return;
    ob->total_len += n;
    const uint8_t *p = d; size_t rem = n;
    if (ob->head_limit == OB_NOLIMIT || ob->head_len < ob->head_limit) {
        size_t room = (ob->head_limit == OB_NOLIMIT) ? rem : ob->head_limit - ob->head_len;
        size_t take = rem < room ? rem : room;
        ob_emit_capped(e, s, p, take);
        ob->head_len += take;
        p += take; rem -= take;
    }
    if (rem > 0) {
        ob->truncated = 1;
        ob_tail_push(ob, p, rem);
    }
}

// Emit the truncation notice + tail once, at end-of-step (or before a pause).
// No-op when nothing was dropped. send_step_done reads ob->truncated for the
// frame flag, so call this just before it.
static void ob_finish(edge_t *e, session_t *s) {
    out_policy_t *ob = &s->ob;
    if (!ob->truncated || ob->notice_sent) return;
    ob->notice_sent = 1;
    size_t dropped = ob->total_len > ob->head_len + ob->tail_len
                   ? ob->total_len - ob->head_len - ob->tail_len : 0;
    char notice[96];
    int m = snprintf(notice, sizeof notice, "\n\n... [truncated %zu chars] ...\n\n", dropped);
    if (m > 0) send_output_bytes(e, s, (const uint8_t *)notice, (size_t)m);
    if (ob->tail_len > 0) {
        // Tail is its own block — start a fresh line-cap column state.
        ob->col = 0; ob->line_dropped = 0;
        ob_emit_capped(e, s, ob->tail, ob->tail_len);
        if (ob->line_limit != OB_NOLIMIT && ob->line_dropped > 0) {
            char suf[32];
            int k = snprintf(suf, sizeof suf, " ...[+%zu chars]", ob->line_dropped);
            if (k > 0) send_output_bytes(e, s, (const uint8_t *)suf, (size_t)k);
            ob->line_dropped = 0;
        }
    }
}

// Returns the number of bytes read this call (0 on EAGAIN/no data), so the
// caller can keep draining while a full buffer suggests more is pending.
static long forward_pty_output(edge_t *e, session_t *s) {
    long n = bridge_pty_read(&s->pty, e->pty_buf, sizeof(e->pty_buf));
    if (n <= 0) return 0;
    s->last_active_ms = monotonic_ms();

    if (s->state != SESS_RUNNING) {
        send_output_bytes(e, s, e->pty_buf, (size_t)n);
        return n;
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
            ob_append(e, s, s->tail_buf, emit);
            memmove(s->tail_buf, s->tail_buf + emit, s->tail_len - emit);
            s->tail_len -= emit;
        }
        return n;
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
        ob_append(e, s, s->tail_buf, skip);
        memmove(s->tail_buf, s->tail_buf + skip, s->tail_len - skip);
        s->tail_len -= skip;
        // Loop hint: caller will run again on next read; if more sentinel
        // candidates already in tail, they'll be discovered then.
        return n;
    }

    if (!has_code) {
        // Incomplete line — emit pre-sentinel bytes, keep candidate.
        // Drop the leading separator our printf injected ("\n" or "\r\n").
        size_t trim_back = 0;
        if (found >= 2 && s->tail_buf[found - 2] == '\r' && s->tail_buf[found - 1] == '\n') trim_back = 2;
        else if (found >= 1 && s->tail_buf[found - 1] == '\n') trim_back = 1;
        size_t emit = (size_t)found - trim_back;
        if (emit > 0) ob_append(e, s, s->tail_buf, emit);
        size_t keep = s->tail_len - (size_t)found;
        memmove(s->tail_buf, s->tail_buf + (size_t)found, keep);
        s->tail_len = keep;
        return n;
    }

    // Success. Emit pre-sentinel bytes minus the injected separator.
    size_t trim_back = 0;
    if (found >= 2 && s->tail_buf[found - 2] == '\r' && s->tail_buf[found - 1] == '\n') trim_back = 2;
    else if (found >= 1 && s->tail_buf[found - 1] == '\n') trim_back = 1;
    size_t pre = (size_t)found - trim_back;
    if (pre > 0) ob_append(e, s, s->tail_buf, pre);

    (void)line_end;  // bytes after the sentinel line are silently dropped (they shouldn't exist).
    ob_finish(e, s);  // emit truncation notice + tail (no-op if nothing dropped)
    send_step_done(e, s, has_code, exit_code, /*timedOut=*/0);
    // run_finish drops the run to SESS_IDLE, and for one-shot sessions also
    // closes the PTY + clears s->active — so the caller's drain loop must
    // re-check s->active before reading again.
    run_finish(s);
    return n;
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
        // STEP_DONE (kept alive only if STEP_AWAITING_INPUT fires first).
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
            // No cwd from agent → fall back to <tmpdir>/todoforai (mirrors edge),
            // so we don't leak whatever pwd the bridge daemon was launched in.
            const char *spawn_cwd = has_cwd ? cwd_buf : resolve_default_cwd();
            if (bridge_pty_spawn(&s->pty, DEFAULT_SHELL, spawn_cwd, /*no_echo=*/1) != 0) {
                free(cmd);
                return send_error(e, NULL, 0, bid, bid_len, "SPAWN_FAILED", "failed to spawn PTY");
            }
            gen_uuid_v4(s->session_id);
            snprintf(s->cwd, sizeof s->cwd, "%s", spawn_cwd);
            s->active = 1;
            s->state = SESS_IDLE;
            s->tail_len = 0;
            s->todo_id_len = 0;
            s->todo_id[0] = '\0';
            s->agent_settings_id_len = 0;
            s->agent_settings_id[0] = '\0';
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

        // Per-RUN agent settings id. Same validation/semantics as todoId:
        // absent ⇒ keep existing, empty ⇒ clear.
        const char *uasi = NULL; size_t uasi_len = 0;
        if (json_get_str(msg, msg_len, "agentSettingsId", &uasi, &uasi_len)) {
            if (uasi_len > 0 && !is_valid_id(uasi, uasi_len)) {
                free(cmd); RUN_FAIL_CLEANUP();
                return send_error(e, NULL, 0, bid, bid_len, "INVALID_AGENT_ID",
                                  "agentSettingsId must be 1-64 chars of [A-Za-z0-9_.-]");
            }
            memcpy(s->agent_settings_id, uasi, uasi_len);
            s->agent_settings_id[uasi_len] = '\0';
            s->agent_settings_id_len = uasi_len;
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

        // Resolve this RUN's output policy from `output` (safe|wide|full|raw).
        // Absent ⇒ "safe". The bridge owns head/tail cut + line cap from here;
        // the backend just concatenates the OUTPUT frames we emit.
        const char *omode = NULL; size_t omode_len = 0;
        json_get_str(msg, msg_len, "output", &omode, &omode_len);
        ob_resolve(&s->ob, omode, omode_len);

        // Wrap cmd in a brace group to capture $? and emit the per-step
        // sentinel. Assumes syntactically complete shell input; background
        // jobs (cmd &) make the sentinel fire at *launch*. Prefix `export`
        // when a device session token is set so tfa-* CLIs authenticate
        // without a real API key. Token (`dst_` + 64 hex), agent id, and
        // api_url are all validated charset-safe.
        size_t wrapped_cap = (size_t)cmd_len + s->sentinel_len
                             + sizeof(e->subagent_token) + sizeof(s->agent_settings_id)
                             + sizeof(e->api_url) + 320;
        char *wrapped = malloc(wrapped_cap);
        if (!wrapped) { free(cmd); RUN_FAIL_CLEANUP(); return send_error(e, NULL, 0, bid, bid_len, "OOM", "out of memory"); }
        int wn;
        if (e->subagent_token[0]) {
            wn = snprintf(wrapped, wrapped_cap,
                "export PAGER=cat GH_PAGER=cat GIT_PAGER=cat MANPAGER=cat SYSTEMD_PAGER=cat AWS_PAGER= "
                "TODOFORAI_API_TOKEN=%s TODOFORAI_API_URL=%s%s%s; { %.*s\n}; __RC=$?; printf '\\n%s:%%d\\n' \"$__RC\"\n",
                e->subagent_token, e->api_url,
                s->agent_settings_id[0] ? " TODOFORAI_AGENT_SETTINGS_ID=" : "",
                s->agent_settings_id[0] ? s->agent_settings_id : "",
                (int)cmd_len, cmd, s->sentinel);
        } else {
            wn = snprintf(wrapped, wrapped_cap,
                "export PAGER=cat GH_PAGER=cat GIT_PAGER=cat MANPAGER=cat SYSTEMD_PAGER=cat AWS_PAGER=; "
                "{ %.*s\n}; __RC=$?; printf '\\n%s:%%d\\n' \"$__RC\"\n",
                (int)cmd_len, cmd, s->sentinel);
        }
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

    } else if (IS("subagent_token")) {
        // Server pushes a short-lived bearer token (dst_…) right after auth.
        // Bridge stashes it on edge_t and exports it as TODOFORAI_API_TOKEN
        // into every PTY's wrapper env (see RUN handler). Per-PTY
        // agentSettingsId travels separately on each RUN message.
        // Refresh = reconnect.
        const char *t = NULL; size_t tlen = 0;
        if (json_get_str(msg, msg_len, "token", &t, &tlen) && tlen > 0 && tlen < sizeof e->subagent_token) {
            memcpy(e->subagent_token, t, tlen);
            e->subagent_token[tlen] = '\0';
            fprintf(stderr, "device session token received (%zu bytes)\n", tlen);
            // Persist as `apiToken` so CLIs invoked outside a bridge-spawned
            // PTY (no TODOFORAI_API_TOKEN in env) can still auth. Refreshed
            // on every reconnect; TTL ~24h matches backend session TTL.
            login_credentials_t upd;
            memset(&upd, 0, sizeof upd);
            if (tlen < sizeof upd.api_token) {
                memcpy(upd.api_token, t, tlen);
                upd.api_token[tlen] = '\0';
                (void)login_save_credentials(&upd);
            }
        } else {
            // Bad/oversized token: clear so we don't leak a partial value into env.
            e->subagent_token[0] = '\0';
            fprintf(stderr, "subagent_token: missing or invalid 'token' field; ignoring\n");
        }

    } else if (IS("input")) {
        // Forward raw stdin bytes — used to resume a RUN awaiting input. The bridge
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
                           : send_error(e, sid, sid_len, NULL, 0, "PTY_WRITE_FAILED", "PTY write failed; session may have died");
        }
        s->last_active_ms = monotonic_ms();
        // Stamp AFTER write_all (see RUN handler comment above).
        s->last_input_ms = s->last_active_ms;
        // Input consumes the prompt: process leaves n_tty_read on the next
        // tick anyway, but reset the counter eagerly to avoid a stale tick
        // re-confirming on the same blocked-read.
        s->pause_consec_ticks = 0;

        if (has_rid) send_ack(e, rid, rid_len);

    } else if (IS("FUNCTION_CALL_REQUEST_AGENT")) {
        // Payload-wrapped: {"payload":{"requestId","agentId","edgeId","functionName","args"}}
        const char *payload = NULL; size_t payload_len = 0;
        if (!json_get_obj(msg, msg_len, "payload", &payload, &payload_len))
            return send_error(e, NULL, 0, NULL, 0, "MISSING_PAYLOAD",
                              "FUNCTION_CALL_REQUEST_AGENT requires payload object");

        const char *req = NULL; size_t req_len = 0;
        if (!json_get_str(payload, payload_len, "requestId", &req, &req_len) || req_len == 0)
            return send_error(e, NULL, 0, NULL, 0, "MISSING_REQUEST_ID",
                              "FUNCTION_CALL_REQUEST_AGENT requires requestId");

        const char *aid = NULL; size_t aid_len = 0;
        json_get_str(payload, payload_len, "agentId", &aid, &aid_len);
        const char *eid = NULL; size_t eid_len = 0;
        json_get_str(payload, payload_len, "edgeId", &eid, &eid_len);

        const char *fn = NULL; size_t fn_len = 0;
        if (!json_get_str(payload, payload_len, "functionName", &fn, &fn_len))
            return send_function_call_error(e, req, req_len, aid, aid_len, eid, eid_len,
                                            "FUNCTION_CALL_REQUEST_AGENT requires functionName");

        const char *args = NULL; size_t args_len = 0;
        json_get_obj(payload, payload_len, "args", &args, &args_len);

        if (fn_len == 10 && memcmp(fn, "scan_tools", 10) == 0) {
            // args = {"entries": "<line-oriented base64 catalog>"}.
            // json_get_str_decoded works on any object substring, so we can
            // call it directly on the nested `args` range (with proper
            // \t/\n/\"/\\ unescape, incl. \uXXXX).
            const char *raw = NULL; size_t raw_len = 0;
            if (!args || !json_get_str(args, args_len, "entries", &raw, &raw_len)) {
                send_function_call_error(e, req, req_len, aid, aid_len, eid, eid_len,
                                         "scan_tools requires args.entries");
                return 0;
            }
            char *buf = malloc(raw_len + 1);
            if (!buf) {
                send_function_call_error(e, req, req_len, aid, aid_len, eid, eid_len, "out of memory");
                return 0;
            }
            size_t entries_len = 0;
            if (!json_get_str_decoded(args, args_len, "entries", buf, raw_len + 1, &entries_len)) {
                free(buf);
                send_function_call_error(e, req, req_len, aid, aid_len, eid, eid_len,
                                         "scan_tools: malformed args.entries");
                return 0;
            }

            char *result = malloc(MAX_MSG);
            if (!result) {
                free(buf);
                send_function_call_error(e, req, req_len, aid, aid_len, eid, eid_len, "out of memory");
                return 0;
            }
            bridge_scan_stats_t stats;
            int n = bridge_scan_tools(buf, entries_len, result, MAX_MSG, &stats);
            free(buf);
            if (n > 0) {
                send_function_call_result(e, req, req_len, aid, aid_len, eid, eid_len, result, (size_t)n);
                fprintf(stderr, "✓ Probed CLI tools: %d installed, %d/%d authenticated (of tools with auth)\n",
                        stats.installed, stats.authenticated, stats.auth_applicable);
            } else {
                send_function_call_error(e, req, req_len, aid, aid_len, eid, eid_len,
                                         "scan_tools failed (overflow or empty catalog)");
                fprintf(stderr, "CLI tool probe failed (overflow or empty)\n");
            }
            free(result);
        } else if (fn_len == 14 && memcmp(fn, "write_file_b64", 14) == 0) {
            // args: {path, dataB64, offset?: N|-1, truncate?: bool}
            //   offset = 0 / omitted → write from start (truncate default=true)
            //   offset = -1          → append (truncate must be false)
            //   offset > 0           → pwrite (truncate default=false)
            // Result: {bytesWritten, totalSize}
            #ifdef _WIN32
            #  define wfb_close(fd)        _close(fd)
            #  define wfb_fstat(fd, st)    _fstati64((fd), (st))
            #  define WFB_STAT             struct _stati64
            #else
            #  define wfb_close(fd)        close(fd)
            #  define wfb_fstat(fd, st)    fstat((fd), (st))
            #  define WFB_STAT             struct stat
            #endif

            #define WFB_FAIL(msg) do { \
                send_function_call_error(e, req, req_len, aid, aid_len, eid, eid_len, (msg)); \
                free(path); free(decoded); \
                if (fd >= 0) wfb_close(fd); \
                return 0; \
            } while (0)

            char *path = NULL, *decoded = NULL;
            int fd = -1;

            const char *praw = NULL; size_t praw_len = 0;
            if (!args || !json_get_str(args, args_len, "path", &praw, &praw_len) || praw_len == 0)
                WFB_FAIL("write_file_b64 requires args.path");
            path = malloc(praw_len + 1);
            if (!path) WFB_FAIL("out of memory");
            size_t plen = 0;
            if (!json_get_str_decoded(args, args_len, "path", path, praw_len + 1, &plen))
                WFB_FAIL("write_file_b64: malformed args.path");
            (void)plen;

            // Expand a leading ~ ourselves — this path never touches the shell.
            char *expanded = bridge_expand_tilde(path);
            if (expanded) { free(path); path = expanded; }

            const char *b64 = NULL; size_t b64_len = 0;
            if (!json_get_str(args, args_len, "dataB64", &b64, &b64_len))
                WFB_FAIL("write_file_b64 requires args.dataB64");

            // json_get_long → `long` is 32-bit on Windows LLP64. The bridge's parser
            // doesn't expose i64; offsets >2GB on Windows aren't supported today.
            long offset = 0;
            json_get_long(args, args_len, "offset", &offset);
            if (offset < -1) WFB_FAIL("write_file_b64: offset must be >= -1");

            int truncate_set = 0, truncate_val = 0;
            if (json_get_bool(args, args_len, "truncate", &truncate_val)) truncate_set = 1;
            // Default: truncate iff we're writing from the start. Append + truncate
            // is incoherent (would truncate to dec_len, corrupting the file).
            int do_truncate = truncate_set ? truncate_val : (offset == 0);
            if (offset < 0 && do_truncate)
                WFB_FAIL("write_file_b64: cannot combine offset=-1 (append) with truncate=true");

            size_t dec_cap = b64_len / 4 * 3 + 4;
            decoded = malloc(dec_cap);
            if (!decoded) WFB_FAIL("out of memory");
            size_t dec_len = b64_decode(b64, b64_len, decoded, dec_cap);
            if (dec_len == 0 && b64_len > 0) WFB_FAIL("write_file_b64: invalid base64");

#ifdef _WIN32
            int flags = _O_WRONLY | _O_CREAT | _O_BINARY;
            if (offset < 0) flags |= _O_APPEND;
            fd = _open(path, flags, _S_IREAD | _S_IWRITE);
#else
            int flags = O_WRONLY | O_CREAT | O_CLOEXEC;
            if (offset < 0) flags |= O_APPEND;
            fd = open(path, flags, 0644);
#endif
            if (fd < 0) WFB_FAIL("write_file_b64: open failed");

            // Write in a loop — handle short writes / EINTR on regular files.
            // pwrite/write on a regular file rarely short-writes, but be safe.
            size_t written = 0;
            while (written < dec_len) {
                long long wn;
                size_t remain = dec_len - written;
#ifdef _WIN32
                if (written == 0 && offset > 0) {
                    if (_lseeki64(fd, (int64_t)offset, SEEK_SET) < 0)
                        WFB_FAIL("write_file_b64: seek failed");
                }
                unsigned int chunk = remain > (1u << 30) ? (1u << 30) : (unsigned int)remain;
                wn = _write(fd, (char *)decoded + written, chunk);
#else
                if (offset > 0) wn = pwrite(fd, (char *)decoded + written, remain, (off_t)offset + (off_t)written);
                else            wn = write(fd,  (char *)decoded + written, remain);
                if (wn < 0 && errno == EINTR) continue;
#endif
                if (wn <= 0) WFB_FAIL("write_file_b64: write failed");
                written += (size_t)wn;
            }

            int64_t end_off = (offset > 0 ? offset : 0) + (int64_t)dec_len;
            if (do_truncate) {
#ifdef _WIN32
                if (_chsize_s(fd, end_off) != 0) WFB_FAIL("write_file_b64: truncate failed");
#else
                if (ftruncate(fd, (off_t)end_off) != 0) WFB_FAIL("write_file_b64: truncate failed");
#endif
            }

            // Total file size after the write (post-truncate if applied).
            WFB_STAT st;
            int64_t total = end_off;
            if (wfb_fstat(fd, &st) == 0) total = (int64_t)st.st_size;
            wfb_close(fd); fd = -1;

            char result[96];
            int rn = snprintf(result, sizeof result,
                              "{\"bytesWritten\":%zu,\"totalSize\":%lld}",
                              dec_len, (long long)total);
            send_function_call_result(e, req, req_len, aid, aid_len, eid, eid_len, result, (size_t)rn);
            free(path); free(decoded);
            #undef WFB_FAIL
            #undef WFB_STAT
            #undef wfb_close
            #undef wfb_fstat
        } else {
            char errmsg[128];
            snprintf(errmsg, sizeof errmsg, "Unknown function: %.*s. Available: scan_tools, write_file_b64",
                     (int)fn_len, fn);
            send_function_call_error(e, req, req_len, aid, aid_len, eid, eid_len, errmsg);
        }
    }

    #undef IS
    return 0;
}

// ── Main loop ───────────────────────────────────────────────────────────────

// Per-tick: reap, deadline, pause-probe, PTY drain (non-blocking).
// Idle sessions live forever; slot pressure handled via LRU on the next RUN.
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
                    ob_append(e, s, s->tail_buf, s->tail_len);
                    s->tail_len = 0;
                }
                ob_finish(e, s);
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
            ob_append(e, s, s->tail_buf, s->tail_len);
            s->tail_len = 0;
        }
        ob_finish(e, s);
        send_step_done(e, s, /*has_code=*/0, 0, /*timedOut=*/1);
        run_finish(s);
    }

    // Awaiting-input probe: see PAUSE_POLL_MS / PAUSE_CONFIRM_TICKS comments above.
    for (int i = 0; i < g_max_sessions; i++) {
        session_t *s = &e->sessions[i];
        if (!s->active || s->state != SESS_RUNNING) continue;
        if (now - s->last_pause_poll_ms < PAUSE_POLL_MS) continue;
        s->last_pause_poll_ms = now;

        // Skip during ldisc-drain after large writes (multi-MB base64) —
        // the shell legitimately sits in read() waiting on *us*, not user stdin.
        if (now - s->last_input_ms < INPUT_GRACE_MS) { s->pause_consec_ticks = 0; continue; }

        long fg = 0; int pwd = 0;
        int blocked = bridge_pty_probe_blocked(&s->pty, /*echo_baseline=*/0, &fg, &pwd);
        if (!blocked) { s->pause_consec_ticks = 0; continue; }
        if (++s->pause_consec_ticks != PAUSE_CONFIRM_TICKS) continue;

        if (s->tail_len > 0) {
            ob_append(e, s, s->tail_buf, s->tail_len);
            s->tail_len = 0;
        }
        ob_finish(e, s);
        // Promote one-shot → persistent so STEP_DONE doesn't tear it down.
        s->one_shot = 0;
        // Drop the per-step deadline: agent owns lifecycle via awaitResume.
        // Otherwise timeout fires STEP_DONE(timedOut) while the user is typing.
        s->deadline_ms = 0;
        send_step_awaiting_input(e, s, pwd);  // reads ob.truncated before reset
        // Post-prompt output is a fresh delta (mirrors edge resetForInteraction).
        ob_reset(&s->ob);
        fprintf(stderr, "RUN awaiting input: %s fg=%ld pwd=%d\n",
                s->run_block_id, fg, pwd);
    }

    // Drain PTY masters (non-blocking; returns 0 on EAGAIN). Drain each session
    // until it stops yielding a full buffer, so large output doesn't trickle
    // one BUF_SIZE chunk per loop tick (which, with the PTY fd in the pollset,
    // would spin the loop). A per-session byte budget keeps one noisy session
    // from starving others; leftover bytes are picked up next tick.
    for (int i = 0; i < g_max_sessions; i++) {
        session_t *s = &e->sessions[i];
        size_t drained = 0;
        // s->active can flip to 0 mid-drain (sentinel → run_finish), so re-check.
        while (s->active && drained < 1u << 20) {
            long n = forward_pty_output(e, s);
            if (n <= 0) break;
            drained += (size_t)n;
        }
    }
}

static void on_ws_msg(uint8_t op, const uint8_t *data, size_t len, void *ctx) {
    edge_t *e = ctx;
    if (op != WS_OP_BINARY) return;
    long n = noise_ws_recv(&e->noise, data, len, e->msg_buf, sizeof(e->msg_buf));
    if (n < 0) {
        fail(e, e->noise.handshake_done
                ? "noise decrypt failed (corrupt frame, replay, or out-of-order)"
                : "noise handshake failed (server identity changed — re-run `todoforai-bridge login`)");
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
    // Derive the public HTTP API URL from the Noise host. In prod a TLS
    // terminator (nginx/Cloudflare) fronts the backend on 443 while the Noise
    // channel rides plain WS on port 80 — so the transport `port` must NOT leak
    // into an https:// URL (that yields the impossible https://host:80, which
    // TLS-handshakes against a plaintext port → "wrong version number"). Only
    // local/dev hosts carry the explicit port through.
    {
        const int local = login_is_local_host(host);
        const char *scheme = local ? "http" : "https";
        if (local && port != 80)
            snprintf(e->api_url, sizeof e->api_url, "%s://%s:%u", scheme, host, (unsigned)port);
        else
            snprintf(e->api_url, sizeof e->api_url, "%s://%s", scheme, host);
    }
    if (noise_ws_init(&e->noise, pubkey) != 0) {
        fail(e, "failed to initialize noise (bad server pubkey?)");
        return -1;
    }
    // ws rx capacity: plaintext MAX_MSG + Noise auth tag (16) + WS header slack.
    if (ws_connect(&e->ws, host, port, path, MAX_MSG + NOISE_TAG_LEN + 16, 10000) != 0) {
        fail(e, "%s", e->ws.err);
        noise_ws_wipe(&e->noise);
        return -1;
    }
    if (noise_ws_start(&e->noise, &e->ws) != 0) {
        fail(e, "failed to start noise handshake");
        ws_close(&e->ws);
        noise_ws_wipe(&e->noise);
        return -1;
    }

    // pfds[0] is always the WS fd; remaining slots are active sessions' PTY
    // master fds so output wakes the loop immediately instead of waiting out
    // the timeout. +1 for the WS slot.
    struct pollfd *pfds = calloc((size_t)g_max_sessions + 1, sizeof *pfds);
    if (!pfds) { fail(e, "out of memory allocating pollfds"); ws_close(&e->ws); noise_ws_wipe(&e->noise); return -1; }

    while (!e->done) {
        pfds[0].fd = e->ws.fd;
        pfds[0].events = POLLIN | (ws_want_write(&e->ws) ? POLLOUT : 0);
#ifdef _WIN32
        ULONG nfds = 1;          // WSAPoll takes ULONG; nfds_t is POSIX-only
#else
        nfds_t nfds = 1;
#endif
        // Poll the PTY of every running session. The session index is recovered
        // from the fd in service_sessions (it reads all active sessions anyway),
        // so we only need the wakeup here — no per-fd bookkeeping.
        for (int i = 0; i < g_max_sessions; i++) {
            session_t *s = &e->sessions[i];
            if (s->active && s->state == SESS_RUNNING) {
                int fd = bridge_pty_pollfd(&s->pty);
                if (fd >= 0) { pfds[nfds].fd = fd; pfds[nfds].events = POLLIN; nfds++; }
            }
        }
        struct pollfd *pfd = &pfds[0];
        // Keep a 50ms ceiling so the awaiting-input probe and deadline checks in
        // service_sessions still tick when neither WS nor PTY has activity.
        int pr = poll(pfds, nfds, 50);
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
            if (pfd->revents & (POLLERR | POLLNVAL)) {
                fail(e, "socket error (revents=0x%x)", pfd->revents);
                break;
            }
            if (pfd->revents & (POLLIN | POLLHUP)) {
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
            if (pfd->revents & POLLOUT) {
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
            if (e->user_email && e->user_email[0])
                fprintf(stderr, "✓ Authenticated as %s\n", e->user_email);
            else
                fprintf(stderr, "✓ Authenticated\n");
        }
        service_sessions(e);
        // Liveness watchdog: catch a half-open socket the kernel never EOFs
        // (e.g. surviving a hibernation, where last_recv_ms suddenly looks far
        // in the past on wake). PING after WS_PING_IDLE_MS, presume dead after
        // WS_DEAD_MS. ws_check_liveness no-ops until the handshake seeds the clock.
        if (ws_check_liveness(&e->ws, WS_PING_IDLE_MS, WS_DEAD_MS)) {
            fail(e, "%s", e->ws.err[0] ? e->ws.err : "connection liveness check failed");
            break;
        }
        // Drain any send queue produced by service_sessions / handle_command
        // (or the watchdog PING above).
        if (ws_want_write(&e->ws) && ws_io_out(&e->ws) < 0) { fail(e, "%s", e->ws.err); break; }
    }
    free(pfds);
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

// Acquire an exclusive per-device lock so two bridge processes can't race
// for the same backend session slot. The kernel releases the lock on exit
// (process death, kill, segfault, …) so there's no stale-lockfile cleanup
// to maintain. Returns 0 on success, -1 if another process holds it.
// Windows: no-op (flock unavailable; relying on server-side flap guard).
#ifndef _WIN32
static int acquire_device_lock(const char *device_id) {
    // device_id is backend-issued `dev_<hex>`; refuse anything that could
    // escape the config dir if the creds file was hand-edited.
    for (const char *p = device_id; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-') return 0;
    }
    char cfg[1024];
    if (login_config_path(cfg, sizeof cfg) < 0) return 0;  // no $HOME → skip
    // Strip "/credentials.json" to get the config dir, then build lock path.
    char *slash = strrchr(cfg, '/');
    if (!slash) return 0;
    *slash = '\0';
    char lock_path[1280];
    snprintf(lock_path, sizeof lock_path, "%s/bridge-%s.lock", cfg, device_id);
    int fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return 0;  // best-effort; don't block startup on FS errors
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        // EWOULDBLOCK is the only "someone else holds it" signal. Anything
        // else means locking is unavailable on this kernel/fs (minimal
        // Firecracker guests return ENOSYS; some FSes return ENOLCK/
        // EOPNOTSUPP) — treat as best-effort and proceed, exactly like an
        // open() failure. Without this, a non-flock fs would falsely report
        // "another bridge running" and the sandbox /init would kernel-panic.
        if (errno != EWOULDBLOCK) { close(fd); return 0; }
        close(fd);
        return -1;
    }
    // Intentionally leak fd — kernel releases the lock on process exit.
    return 0;
}
#endif

int main(int argc, char **argv) {
    // Swap in any binary staged by a prior `exec` update. See update.h.
    bridge_update_swap_on_start(argv[0]);

    // Subcommand dispatch before option parsing so `bridge login -h` works.
    if (argc >= 2 && strcmp(argv[1], "login") == 0) {
        int rc = cmd_login(argc - 1, argv + 1);
        if (rc == CMD_RC_HELP) return 0;
        if (rc != 0) return rc;
        argc = 1;   // fall through into daemon
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

    const char *host = NULL, *port_s = NULL, *profile = NULL;
    ko_longopt_t longopts[] = {
        { "help",          ko_no_argument,       'h' },
        { "host",          ko_required_argument, 'H' },
        { "port",          ko_required_argument, 'p' },
        { "profile",       ko_required_argument, 'P' },
        { 0, 0, 0 }
    };
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "hH:p:P:", longopts)) >= 0) {
        if      (c == 'h') { print_help(); return 0; }
        else if (c == 'H') host = opt.arg;
        else if (c == 'p') port_s = opt.arg;
        else if (c == 'P') profile = opt.arg;
        else cli_parse_error("todoforai-bridge", USAGE_MAIN, argc, argv, &opt, c);
    }
    // Select the credential profile before any load (env is last resort).
    // When --host points at a local/dev backend but no --profile was given,
    // default to the "dev" profile instead of "default": dev creds are minted
    // against the local backend (own device id/secret + TOFU'd pubkey), so the
    // prod-pinned default profile would otherwise fail the Noise handshake.
    if (!profile && login_is_local_host(host)) profile = "dev";
    if (profile && login_set_profile(profile) < 0) return 2;

    // Load saved device credentials from `bridge login`
    login_credentials_t saved_creds;
    memset(&saved_creds, 0, sizeof(saved_creds));
    (void)login_load_credentials(&saved_creds);

    // No creds → run login inline, then fall through to daemon.
    // Sandbox/systemd setups pre-provision via `login --token` and skip this.
    if (!saved_creds.device_id[0] || !saved_creds.device_secret[0]) {
        fprintf(stderr, "No device credentials found. Starting login...\n\n");
        // Forward --host only; --port here is BRIDGE_PORT (HTTP/WS), not Noise.
        int rc = bridge_login_run(NULL, NULL, host, NULL);
        if (rc != 0) return rc;
        if (login_load_credentials(&saved_creds) < 0
            || !saved_creds.device_id[0] || !saved_creds.device_secret[0]) {
            fprintf(stderr, "error: login completed but no credentials saved.\n");
            return 1;
        }
    }

    // Precedence: --host flag → saved profile creds → env → prod default.
    if (!host && saved_creds.backend_host[0]) host = saved_creds.backend_host;
    if (!host) host = getenv("NOISE_BACKEND_HOST");
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

    // The Noise pubkey was pinned during `login` (TOFU on the NX handshake).
    // No flag, no env, no hardcoded default — just what we learned on day one.
    if (!saved_creds.backend_pubkey[0]) {
        fprintf(stderr,
            "error: credentials are missing the backend pubkey.\n"
            "Run `todoforai-bridge logout && todoforai-bridge login` to refresh.\n");
        return 1;
    }
    uint8_t server_pubkey[32];
    if (parse_pubkey_hex(saved_creds.backend_pubkey, server_pubkey) != 0) {
        fprintf(stderr, "error: stored backend pubkey is corrupt (re-run `todoforai-bridge login`).\n");
        return 1;
    }

    // Refuse to start if another bridge process on this machine is already
    // running for the same device. Without this, two bridges flap-loop kicking
    // each other off the server (close code 4000) every ~1s.
#ifndef _WIN32
    if (acquire_device_lock(saved_creds.device_id) < 0) {
        fprintf(stderr,
            "error: another todoforai-bridge is already running for device %.8s… on this machine.\n"
            "       Stop it first (`pgrep -af todoforai-bridge`) or remove the duplicate from pm2/systemd.\n",
            saved_creds.device_id);
        return 1;
    }
#endif

    // Show 8-char device id prefix so the trailing "..." reads as "connecting…"
    // rather than "id truncated". Full id is in ~/.config/todoforai/credentials.json.
    fprintf(stderr, "Connecting to %s:%u (device: %.8s…, bridge %s) ...\n",
            host, (unsigned)port, saved_creds.device_id, BRIDGE_VERSION);

    g_max_sessions = resolve_max_sessions();
    // Each session needs a master fd + a few transient pipes in the child
    // spawn path. Add headroom for the bridge's own fds (ws, stdio, etc.).
    bump_fd_limit(g_max_sessions + 64);

    edge_t *e = calloc(1, sizeof(*e));
    if (!e) return 1;
    e->sessions = calloc((size_t)g_max_sessions, sizeof(*e->sessions));
    if (!e->sessions) { free(e); return 1; }
    e->user_email = saved_creds.user_email;  // safe: saved_creds outlives the run loop

    // Reconnect loop. PTY sessions survive across reconnects; in-flight RPCs
    // are rejected by handleClose, not replayed.
    const int max_attempts_pre_auth  = 20;   // ~17 min — surfaces setup mistakes
    const int max_attempts_post_auth = 60;   // ~5 h   — rides out server outages
    int attempt = 0;
    int ever_authenticated = 0;
    int relogin_attempted = 0;  // one auto re-enroll per 4401 streak
    char last_err_shown[sizeof e->err_msg] = {0};
    int rc;
    for (;;) {
        rc = run(e, saved_creds.device_id, saved_creds.device_secret,
                 host, port, DEFAULT_PATH, server_pubkey);
        if (rc == 0) break;

        int was_authenticated = e->identity_sent;
        if (was_authenticated) ever_authenticated = 1;

        if (e->got_close_frame) {
            const char *reason = e->close_reason[0] ? e->close_reason : "(no reason)";
            fprintf(stderr, "Disconnected by server (code=%u): %s.\n", e->close_code, reason);
            last_err_shown[0] = '\0';
        } else {
            const char *msg = e->err_msg[0] ? e->err_msg : "(no diagnostic — please report)";
            if (strcmp(msg, last_err_shown) != 0) {
                fprintf(stderr, "Connection failed: %s.\n", msg);
                snprintf(last_err_shown, sizeof last_err_shown, "%s", msg);
            }
        }

        if (e->got_close_frame && e->close_code == 4401) {
            // Stale creds (device removed or secret rotated server-side).
            // Self-heal: clear them and re-run the same login flow first-run
            // uses, then reload and keep the loop going. Guarded to one attempt
            // per disconnect so a persistently failing login can't tight-loop.
            if (!relogin_attempted) {
                relogin_attempted = 1;
                fprintf(stderr, "Device credentials rejected — re-enrolling this device...\n");
                login_logout("todoforai-bridge");
                if (bridge_login_run(NULL, NULL, host, NULL) == 0
                    && login_load_credentials(&saved_creds) == 0
                    && saved_creds.device_id[0] && saved_creds.device_secret[0]
                    && saved_creds.backend_pubkey[0]
                    && parse_pubkey_hex(saved_creds.backend_pubkey, server_pubkey) == 0) {
                    attempt = 0;
                    reset_connection_state(e);
                    continue;
                }
            }
            fprintf(stderr, "Re-run `todoforai-bridge login` (device removed or secret rotated).\n");
            break;
        }

        if (was_authenticated) { attempt = 0; relogin_attempted = 0; }  // healthy drop → fresh budget
        ++attempt;
        int max_attempts = ever_authenticated ? max_attempts_post_auth : max_attempts_pre_auth;
        if (attempt >= max_attempts) {
            fprintf(stderr, "Giving up after %d attempts.\n", max_attempts);
            break;
        }

        // Backoff: 1, then 2s for the first several retries so a routine
        // backend restart (down ~20s) is ridden out with tight polling, then
        // exponential 4, 8, 16, … capped at 300s.
        int delay = attempt <= 1 ? 1
                  : attempt <= 6 ? 2
                  :                (1 << (attempt - 5)) > 300 ? 300 : (1 << (attempt - 5));
        fprintf(stderr, "Reconnecting in %ds (attempt %d/%d)...\n", delay, attempt, max_attempts);
#ifdef _WIN32
        Sleep((DWORD)delay * 1000);
#else
        // No SIGINT handler installed — default disposition terminates the
        // process during sleep(), which is the desired behavior for Ctrl+C.
        sleep((unsigned)delay);
#endif
        reset_connection_state(e);
    }

    for (int i = 0; i < g_max_sessions; i++) {
        if (e->sessions[i].active) bridge_pty_close(&e->sessions[i].pty);
    }
    free(e->sessions);
    free(e);
    return rc == 0 ? 0 : 1;
}
