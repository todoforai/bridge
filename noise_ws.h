// Noise_NX shim that runs on top of a mongoose WebSocket connection.
// Stays out of mongoose's way: caller drives the handshake from MG_EV_WS_*
// events, and uses noise_ws_send/_recv for transport-mode app messages.
#ifndef BRIDGE_NOISE_WS_H
#define BRIDGE_NOISE_WS_H

#include <stddef.h>
#include <stdint.h>

#include "noise.h"

struct mg_connection;

typedef struct {
    int               handshake_done;   // 1 after split
    noise_handshake_t hs;
    noise_transport_t transport;
    uint8_t           server_pubkey[32];
} noise_ws_t;

// Init state with the pinned server static pubkey. Returns 0 / -1.
int noise_ws_init(noise_ws_t *n, const uint8_t server_pubkey[32]);

// Send Noise msg1 (initiator e). Call from MG_EV_WS_OPEN.
int noise_ws_start(noise_ws_t *n, struct mg_connection *c);

// Process an incoming WS binary frame.
//   On handshake msg2 → split into transport, returns 0 (no app payload).
//   In transport mode → decrypt into out, returns plaintext length (>0).
//   Returns -1 on error.
long noise_ws_recv(noise_ws_t *n,
                   const uint8_t *frame, size_t frame_len,
                   uint8_t *out, size_t out_cap);

// Send `pt[pt_len]` as one Noise-encrypted WS binary frame. Returns 0 / -1.
int noise_ws_send(noise_ws_t *n, struct mg_connection *c,
                  const uint8_t *pt, size_t pt_len);

void noise_ws_wipe(noise_ws_t *n);

#endif
