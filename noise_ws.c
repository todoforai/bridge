#include "noise_ws.h"

#include <stdio.h>
#include <string.h>

#include "mongoose.h"

int noise_ws_init(noise_ws_t *n, const uint8_t server_pubkey[32]) {
    memset(n, 0, sizeof(*n));
    memcpy(n->server_pubkey, server_pubkey, 32);
    return noise_handshake_init(&n->hs, server_pubkey);
}

int noise_ws_start(noise_ws_t *n, struct mg_connection *c) {
    uint8_t msg1[32];
    int n1 = noise_handshake_write(&n->hs, NULL, 0, msg1, sizeof(msg1));
    if (n1 < 0) return -1;
    return mg_ws_send(c, msg1, (size_t)n1, WEBSOCKET_OP_BINARY) > 0 ? 0 : -1;
}

long noise_ws_recv(noise_ws_t *n,
                   const uint8_t *frame, size_t frame_len,
                   uint8_t *out, size_t out_cap) {
    if (!n->handshake_done) {
        // msg2 from responder: e, ee, s, es — 96 bytes, no app payload.
        uint8_t scratch[64];
        int pn = noise_handshake_read(&n->hs, frame, frame_len,
                                      scratch, sizeof(scratch));
        if (pn < 0) return -1;
        if (noise_handshake_split(&n->hs, &n->transport) != 0) return -1;
        n->handshake_done = 1;
        return 0;
    }
    return noise_transport_read(&n->transport, out, out_cap, frame, frame_len);
}

int noise_ws_send(noise_ws_t *n, struct mg_connection *c,
                  const uint8_t *pt, size_t pt_len) {
    if (!n->handshake_done) return -1;
    // Stack buffer sized to the bridge's MAX_MSG (64K) + Noise tag.
    uint8_t ct[65 * 1024];
    if (pt_len + NOISE_TAG_LEN > sizeof(ct)) return -1;
    int cn = noise_transport_write(&n->transport, ct, sizeof(ct), pt, pt_len);
    if (cn < 0) return -1;
    return mg_ws_send(c, ct, (size_t)cn, WEBSOCKET_OP_BINARY) > 0 ? 0 : -1;
}

void noise_ws_wipe(noise_ws_t *n) {
    noise_wipe(&n->hs, sizeof(n->hs));
    noise_wipe(&n->transport, sizeof(n->transport));
    memset(n, 0, sizeof(*n));
}
