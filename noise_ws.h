// Noise_NX shim that runs on top of a ws_t WebSocket connection.
// Caller drives the handshake explicitly: send msg1 once after connect,
// process msg2 from the first inbound binary frame, then use noise_ws_send /
// noise_ws_recv for transport-mode app messages.
#ifndef BRIDGE_NOISE_WS_H
#define BRIDGE_NOISE_WS_H

#include <stddef.h>
#include <stdint.h>

#include "noise.h"
#include "ws.h"

typedef struct {
    int               handshake_done;   // 1 after split
    noise_handshake_t hs;
    noise_transport_t transport;
} noise_ws_t;

int noise_ws_init(noise_ws_t *n, const uint8_t server_pubkey[32]);

// Send Noise msg1 (initiator e). Call once, immediately after ws_connect.
int noise_ws_start(noise_ws_t *n, ws_t *w);

// Process one inbound WS binary frame.
//   Pre-handshake → expects msg2; on success transitions to transport, returns 0.
//   Transport     → decrypts into out, returns plaintext length (>0).
//   Returns -1 on error.
long noise_ws_recv(noise_ws_t *n,
                   const uint8_t *frame, size_t frame_len,
                   uint8_t *out, size_t out_cap);

// Encrypt + enqueue a single Noise transport frame. Returns 0 / -1.
int noise_ws_send(noise_ws_t *n, ws_t *w,
                  const uint8_t *pt, size_t pt_len);

void noise_ws_wipe(noise_ws_t *n);

#endif
