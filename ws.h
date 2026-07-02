// Minimal RFC 6455 WebSocket client. ws:// only (Noise is layered on top).
// Single outbound connection, non-blocking after upgrade, poll()-friendly.
// Server frames must be non-fragmented (FIN=1). Auto-PONGs PINGs.
// Not thread-safe — owned by one thread.
#ifndef BRIDGE_WS_H
#define BRIDGE_WS_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#  include <winsock2.h>
typedef SOCKET ws_fd_t;
#else
typedef int ws_fd_t;
#endif

// RFC 6455 opcodes (only the ones we use).
#define WS_OP_CONT   0x0
#define WS_OP_TEXT   0x1
#define WS_OP_BINARY 0x2
#define WS_OP_CLOSE  0x8
#define WS_OP_PING   0x9
#define WS_OP_PONG   0xA

typedef struct {
    ws_fd_t  fd;
    int      closed;             // peer CLOSE / TCP EOF / fatal error
    int      sent_close;         // our CLOSE reply enqueued

    // Recv: one in-progress frame, up to MAX_MSG.
    uint8_t *rx;
    size_t   rx_len, rx_cap;

    // Send queue: framed bytes waiting on the wire.
    uint8_t *tx;
    size_t   tx_len, tx_cap;

    uint16_t close_code;
    int      have_close;
    char     close_reason[128];

    // Liveness: monotonic ms of the last byte read off the socket, and of the
    // last app-level PING we sent. Driven by the caller's watchdog so a
    // half-open socket (hibernation, silent network drop) is surfaced even when
    // the kernel never delivers an EOF.
    int64_t  last_recv_ms;
    int64_t  ping_sent_ms;

    char     err[160];
} ws_t;

// TCP connect + HTTP Upgrade + verify 101 + set non-blocking + alloc rx/tx.
// Does NOT validate Sec-WebSocket-Accept: Noise authenticates the server,
// so a bogus 101 fails the handshake anyway (and avoids bundling SHA-1).
// Returns 0 on success; ws->err on failure.
int ws_connect(ws_t *ws, const char *host, uint16_t port, const char *path,
               size_t max_msg, int connect_timeout_ms);

void ws_close(ws_t *ws);

// Frame and enqueue. Caller drains via ws_io_out on POLLOUT.
int ws_send_frame(ws_t *ws, uint8_t opcode, const void *data, size_t len);

// Ensure the TX queue can accept a frame with `len` payload bytes (WebSocket
// header/mask overhead is accounted for internally).
// Tries a synchronous drain first, then grows the buffer up to WS_TX_MAX.
// Returns 0 if room is guaranteed, -1 otherwise. Callers that pay a
// non-replayable cost to build a frame (e.g. a Noise nonce) MUST call this
// before building it, so a full queue never burns that cost.
#define WS_TX_MAX (8u * 1024 * 1024)
int ws_ensure_tx_room(ws_t *ws, size_t len);

// Drain as much of the send queue as the kernel will accept.
int ws_io_out(ws_t *ws);

// Pull bytes; invoke `cb` per complete app frame.
// PING → auto-PONG; CLOSE → record + reply + mark closed; PONG → ignored.
typedef void (*ws_recv_cb)(uint8_t opcode, const uint8_t *data, size_t len, void *ctx);
int ws_io_in(ws_t *ws, ws_recv_cb cb, void *ctx);

static inline int ws_want_write(const ws_t *ws) { return ws->tx_len > 0; }

// Monotonic milliseconds for the liveness watchdog. Uses a clock that counts
// suspend time where available (CLOCK_BOOTTIME / GetTickCount64) so a resume
// from hibernation immediately shows a large idle gap.
int64_t ws_monotonic_ms(void);

// Liveness watchdog. Call once per poll tick. If the socket has been silent for
// `idle_ms`, enqueue an app-level PING (once). If still silent `dead_ms` after
// connect-or-last-byte, mark the connection dead (sets ws->closed + ws->err) so
// the caller breaks its loop and reconnects. Returns 1 if it just declared the
// connection dead, else 0. Catches half-open sockets the kernel never EOFs
// (e.g. surviving a hibernation), which TCP keepalive's ~2h defaults miss.
#define WS_PING_IDLE_MS 30000   // silence before we poke the peer with a PING
#define WS_DEAD_MS      45000   // silence before the connection is presumed dead
int ws_check_liveness(ws_t *ws, int idle_ms, int dead_ms);

#endif
