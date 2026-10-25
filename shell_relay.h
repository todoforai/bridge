// Shell relay: CLIs inside a RUN (`tfa-cat`, the tail shim's `__live`) hand
// bytes to this daemon over loopback; we forward them to the backend on the
// existing Noise channel (SHELL_OPEN / SHELL_DATA / SHELL_END → SHELL_CLOSE,
// see packages/shared-fbe bridgeProtocol.ts). No curl, no TLS handshake per
// call, the same code on every OS.
//
// The daemon listens on an ephemeral 127.0.0.1 port, exported to every RUN as
// TODOFORAI_BRIDGE_PORT (so a mayfly or a second bridge serves its own shells).
// Wire, per connection:
//   client → {"kind":"attach"|"live","token":…,"todoId":…,"blockId":…,
//             "messageId":…,"name":…,"mime":…,"size":N}\n  then raw bytes, then half-close
//   daemon → "ok\n" | "error: <reason>\n", then close
// A `fetch` (`tfa-cat todoforai:…`) sends {"kind":"fetch","ref":…,"tty":true?}\n
// and keeps its write side open (closing it = giving up); the daemon answers
//   "data <size> <mime>\n" + exactly <size> bytes, then close  — the resource
//   "ok\n"     — the backend attached it to the block (image/PDF on a tty)
//   "error: <reason>\n"
// A body shorter than <size> means the transfer broke.
// An attach declares `size`; anything but exactly that many bytes before EOF
// (a killed client, a shrinking file) is aborted and stored nowhere. Every
// state has a deadline, so a stuck or hostile local client can't pin a slot.
// The backend checks the token against a live run for that block; the daemon
// only relays. A rejected stream is drained to EOF before the reply, so the
// client always reads it.
#ifndef BRIDGE_SHELL_RELAY_H
#define BRIDGE_SHELL_RELAY_H

#include "ws.h"  // ws_fd_t, struct pollfd (winsock2 on Windows)
#ifndef _WIN32
#  include <poll.h>
#endif
#include <stddef.h>
#include <stdint.h>

#define SHELL_MAX_STREAMS 16
#define SHELL_DATA_CHUNK  (40 * 1024)   // raw bytes per SHELL_DATA (b64 < 64KB Noise cap)
#define SHELL_HDR_CAP     2048
#define SHELL_REPLY_MS    60000         // END → backend CLOSE; then "error: timeout"
#define SHELL_HDR_MS      5000          // accept → header line
#define SHELL_IDLE_MS     30000         // attach: max gap between reads
#define SHELL_DRAIN_MS    10000         // rejected: wait for the client's EOF
#define SHELL_LIVE_IDLE_MS (10 * 60000) // live: silent this long → stop relaying (the tee goes on)
#define SHELL_FETCH_MAX   (20L * 1024 * 1024 + 256)  // fetch: body bytes buffered for a slow client

// `live` streams (tail shim) are throttled here, not in the CLI: the CLI is a
// plain tee, and we batch lines (≤ every SHELL_LIVE_FLUSH_MS, ≤ SHELL_LIVE_LINES_PER_S,
// lines cut to SHELL_LIVE_LINE_LEN). A live stream is always read, never
// back-pressured: overflow drops lines ("[… N lines]"), and the client's
// sends are non-blocking (shell_client_send_lossy), so the pipeline never waits.
#define SHELL_LIVE_FLUSH_MS    200
#define SHELL_LIVE_FLUSH_BYTES (16 * 1024)
#define SHELL_LIVE_BUF         (64 * 1024)
#define SHELL_LIVE_LINES_PER_S 10
#define SHELL_LIVE_LINE_LEN    300

typedef struct {
    ws_fd_t fd;            // accepted local socket, WS_INVALID_FD when free
    uint32_t id;           // streamId on the wire (never reused)
    int state;             // see shell_relay.c
    int live;              // kind == "live"
    int fetch;             // kind == "fetch"
    char hdr[SHELL_HDR_CAP];
    size_t hdr_len;
    char err[200];         // backend's early rejection, replied after EOF
    int64_t deadline_ms;   // current state's deadline
    long size, got;        // attach: declared / received bytes; fetch: announced / received
    int ready;             // fetch: "data …" line queued
    // fetch: bytes for the client, drained on POLLOUT
    char *outq; size_t outq_len, outq_cap;
    // live only
    char *lbuf; size_t llen;
    int64_t first_ms;      // when the oldest unsent byte arrived
    size_t skipped;        // lines dropped since the last flush
    double credits; int64_t refill_ms;
} shell_stream_t;

typedef int (*shell_send_fn)(void *ctx, const char *json, size_t len);
// 1 while the Noise send queue is backed up: stop reading clients.
typedef int (*shell_busy_fn)(void *ctx);
// 1 when the backend channel is up (authenticated).
typedef int (*shell_ready_fn)(void *ctx);

typedef struct {
    ws_fd_t listen_fd;
    uint16_t port;
    shell_stream_t streams[SHELL_MAX_STREAMS];
    uint32_t next_id;
    shell_send_fn send;
    shell_busy_fn busy;
    shell_ready_fn ready;
    void *ctx;
} shell_relay_t;

// Opens the loopback listener (port 0 when that fails; the relay is then inert).
void shell_relay_init(shell_relay_t *r, shell_send_fn send, shell_busy_fn busy, shell_ready_fn ready, void *ctx);
void shell_relay_close_all(shell_relay_t *r);

// poll() integration, like adb_relay.
void shell_relay_fill_pfds(shell_relay_t *r, struct pollfd *pfds, size_t *n, size_t cap);
void shell_relay_service(shell_relay_t *r, const struct pollfd *pfds, size_t first, size_t n);
// Deadlines + live flushes (call every loop tick).
void shell_relay_tick(shell_relay_t *r);

// SHELL_CLOSE from the backend. `payload` spans the JSON payload object.
void shell_relay_on_close(shell_relay_t *r, const char *payload, size_t len);
// SHELL_READY / SHELL_DATA from the backend (a `fetch` body).
void shell_relay_on_ready(shell_relay_t *r, const char *payload, size_t len);
void shell_relay_on_data(shell_relay_t *r, const char *payload, size_t len);
// Backend connection lost: fail every stream (the backend forgot them).
void shell_relay_drop_streams(shell_relay_t *r, const char *why);

int shell_relay_stream_count(const shell_relay_t *r);

// ── Client side (tfa-cat, __live) ──
// Connects to 127.0.0.1:$TODOFORAI_BRIDGE_PORT and sends the header line built
// from the RUN env (token, todo, block, message ids). Returns the socket
// (blocking) or WS_INVALID_FD with `err`.
// `size`: an attach's exact byte count (-1 otherwise). `ref`: a fetch's URI
// (`tty`: stdout is the agent's terminal), NULL otherwise.
ws_fd_t shell_client_open(const char *kind, const char *name, const char *mime, long size,
                          const char *ref, int tty, char *err, size_t err_cap);
// Fetch: read the daemon's first line. Returns 1 = body follows (`size`,
// `mime` set), 0 = attached (nothing to print), -1 = error (in err).
int shell_client_fetch_head(ws_fd_t fd, long *size, char *mime, size_t mime_cap, char *err, size_t err_cap);
// Blocking read with the SHELL_IDLE_MS timeout. >0 bytes, 0 EOF, -1 error.
long shell_client_recv(ws_fd_t fd, void *p, size_t n);
// Half-close, then read the daemon's reply. NULL = ok, else the reason (in err).
const char *shell_client_finish(ws_fd_t fd, int timeout_ms, char *err, size_t err_cap);
// Blocking send of all bytes. 0 / -1.
int shell_client_send(ws_fd_t fd, const void *p, size_t n);
// Plain close = EOF (a live stream ends normally).
void shell_client_close(ws_fd_t fd);
// Live: never blocks — what doesn't fit the socket buffer now is dropped.
// 0, or -1 once the daemon is gone.
int shell_client_send_lossy(ws_fd_t fd, const void *p, size_t n);

// Body for one live flush (exposed for tests): "[… N lines]" if any were
// skipped, then the last `keep` lines of src[0..n) (n ends on '\n'), each cut
// to SHELL_LIVE_LINE_LEN.
size_t shell_live_body(char *dst, size_t cap, size_t skipped, const char *src, size_t n, size_t keep);

#endif
