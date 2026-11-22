// live_preview WebSocket relay, bridge side — mirrors edge/bun/src/preview.ts
// WS handlers and follows adb_relay's main-loop poll() pattern.
//
// Inbound frames from the backend:
//   preview:ws_open  {streamId, port, path, protocols?}
//   preview:ws_data  {streamId, binary?, dataB64?, text?, fin?}
//   preview:ws_close {streamId, code?, reason?}
//
// Outbound frames to the backend (chunked <= 32KB raw to stay under 64KB Noise cap):
//   preview:ws_opened {streamId, error?}
//   preview:ws_data   {streamId, binary, dataB64, fin}
//   preview:ws_close  {streamId, code?, reason?}
#ifndef BRIDGE_PREVIEW_WS_H
#define BRIDGE_PREVIEW_WS_H

#include "ws.h"
#ifndef _WIN32
#  include <poll.h>
#endif
#include <stddef.h>
#include <stdint.h>

#define PREVIEW_WS_MAX_STREAMS 32
#define PREVIEW_WS_ID_CAP      64
#define PREVIEW_WS_CHUNK_RAW   (32 * 1024)       // ~43KB base64 + envelope < 64KB Noise cap
#define PREVIEW_WS_MAX_MSG     (1024 * 1024)     // 1MB max single WS message (matches PreviewRelay)

typedef int (*preview_ws_send_fn)(void *ctx, const char *json, size_t len);
typedef int (*preview_ws_busy_fn)(void *ctx);

typedef struct {
    int   active;
    char  id[PREVIEW_WS_ID_CAP];
    ws_t  ws;
    // Reassembly buffer for chunked backend -> local messages (fin=false).
    uint8_t *rx_buf;
    size_t   rx_len, rx_cap;
    int      rx_binary;
} preview_ws_stream_t;

typedef struct {
    preview_ws_stream_t streams[PREVIEW_WS_MAX_STREAMS];
    preview_ws_send_fn  send;
    preview_ws_busy_fn  busy;
    void               *send_ctx;
} preview_ws_relay_t;

void preview_ws_init(preview_ws_relay_t *r, preview_ws_send_fn send,
                     preview_ws_busy_fn busy, void *ctx);
void preview_ws_close_all(preview_ws_relay_t *r);

void preview_ws_on_open(preview_ws_relay_t *r, const char *payload, size_t len);
void preview_ws_on_data(preview_ws_relay_t *r, const char *payload, size_t len);
void preview_ws_on_close(preview_ws_relay_t *r, const char *payload, size_t len);

void preview_ws_fill_pfds(preview_ws_relay_t *r, struct pollfd *pfds, size_t *n, size_t cap);
void preview_ws_service(preview_ws_relay_t *r, const struct pollfd *pfds, size_t first, size_t n);

#endif
