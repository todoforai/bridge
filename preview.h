// live_preview relay, bridge side — mirrors edge/bun/src/preview.ts.
//
// The backend forwards HTTP requests from https://<slug>.todofor.ai as
// `preview:http_request` frames; we fetch them from 127.0.0.1:<port> and
// answer with `preview:http_response_chunk` frames. Noise transport messages
// are capped at 65,535 bytes, so the response body is split across chunks:
// seq=0 carries status/headers/setCookie (no body), seq>=1 carry base64 body
// slices, `done:true` marks the last frame. On failure a terminal frame with
// `error` (+ done:true) is sent and the receiver discards accumulated bytes.
//
// Only ports explicitly registered via the live_preview tool are served —
// a leaked session URL can never browse arbitrary local ports.
#ifndef BRIDGE_PREVIEW_H
#define BRIDGE_PREVIEW_H

#include <stddef.h>

// Emit one ready-to-send JSON message (the caller Noise-encrypts + enqueues).
// Return 0 on success, -1 to abort the remaining chunks.
typedef int (*preview_emit_fn)(void *ctx, const char *json, size_t len);

// Allowlist a port for 24h (re-registering refreshes the TTL).
void bridge_preview_allow_port(int port);

// TCP-probe 127.0.0.1:port so registration fails fast when nothing listens.
// Returns 0 if something accepted the connection, -1 with `err` filled.
int bridge_preview_probe_port(int port, char *err, size_t err_cap);

// Handle one `preview:http_request` payload object:
//   {requestId, port, method, path, headers{}, bodyB64?}
// Fetches from 127.0.0.1:<port> (blocking, bounded by an internal deadline)
// and emits preview:http_response_chunk frames via `emit`. Never fails the
// caller: all errors surface as terminal error frames (when requestId is
// parseable) or are logged and dropped.
void bridge_preview_handle_request(const char *payload, size_t payload_len,
                                   preview_emit_fn emit, void *ctx);

#endif
