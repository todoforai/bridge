// Minimal RFC 6455 WebSocket client. Single connection, sync connect,
// non-blocking I/O after upgrade, single-thread poll() friendly.
//
// Scope (deliberately narrow):
//   - ws:// only (no TLS — Noise is layered on top, no plaintext on the wire).
//   - One outbound connection per ws_t.
//   - Server frames must arrive non-fragmented (FIN=1 on the first frame).
//     Our server side never fragments, so this is enforceable.
//   - Auto-replies to PING with PONG; surfaces CLOSE frames + payload.
//   - Bring-your-own event loop: caller poll()s ws_fd(); calls ws_io_in /
//     ws_io_out / ws_send_*; ws_want_write() tells you whether to set POLLOUT.
//
// Thread safety: none. Owned by exactly one thread.
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
    int      closed;             // 1 once peer CLOSE seen / TCP EOF / fatal error
    int      sent_close;         // 1 once we've enqueued our CLOSE reply

    // Recv accumulator. Holds one in-progress frame's bytes up to MAX_MSG.
    uint8_t *rx;
    size_t   rx_len;
    size_t   rx_cap;

    // Send queue. Bytes already framed (header+payload), waiting on the wire.
    uint8_t *tx;
    size_t   tx_len;
    size_t   tx_cap;

    // Last close frame (peer-sent or synthesized for transport errors).
    uint16_t close_code;
    int      have_close;
    char     close_reason[128];

    // Last error message (ws_connect / ws_io_*).
    char     err[160];
} ws_t;

// Connect ws://host:port/path with a deadline (ms). Performs TCP connect,
// sends HTTP Upgrade, reads response, verifies "101 Switching Protocols",
// switches the socket to non-blocking, allocates rx/tx buffers of `max_msg`.
//
// We deliberately do NOT validate Sec-WebSocket-Accept. Reasoning:
//   1. Noise on top cryptographically authenticates the server; a transparent
//      proxy that returned 101 by accident would fail the Noise handshake,
//      surfacing a clear error instead of a generic protocol mismatch.
//   2. Skipping it lets us avoid bundling SHA-1 just for one handshake.
//
// Returns 0 on success. On failure, ws->err holds the reason.
int ws_connect(ws_t *ws, const char *host, uint16_t port, const char *path,
               size_t max_msg, int connect_timeout_ms);

// Free buffers + close socket. Safe on already-closed ws_t.
void ws_close(ws_t *ws);

// Frame `data[len]` with `opcode` (binary/text/close/ping/pong), append to
// the send queue. Caller must drain via ws_io_out when poll() says writable.
// Returns 0 on success, -1 on overflow / closed.
int ws_send_frame(ws_t *ws, uint8_t opcode, const void *data, size_t len);

// Drain as much of the send queue as the kernel will accept right now.
// Returns 0 on success (incl. partial), -1 on fatal error.
int ws_io_out(ws_t *ws);

// Pull bytes from the kernel; on each complete app frame, invoke `cb` with
// (opcode, data, len, ctx). PING/PONG/CLOSE are handled internally:
//   - PING → enqueue PONG with same payload
//   - CLOSE → record code/reason, enqueue our CLOSE reply, mark ws->closed
//   - PONG → ignored
// Returns 0 on success, -1 on fatal frame error / EOF.
typedef void (*ws_recv_cb)(uint8_t opcode, const uint8_t *data, size_t len, void *ctx);
int ws_io_in(ws_t *ws, ws_recv_cb cb, void *ctx);

// 1 if we have queued bytes to write — caller should set POLLOUT.
static inline int ws_want_write(const ws_t *ws) { return ws->tx_len > 0; }

#endif
