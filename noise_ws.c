#include "noise_ws.h"

#include <string.h>

#include "ws.h"

int noise_ws_init(noise_ws_t *n, const uint8_t server_pubkey[32]) {
    memset(n, 0, sizeof(*n));
    return noise_handshake_init(&n->hs, server_pubkey);
}

int noise_ws_start(noise_ws_t *n, ws_t *w) {
    uint8_t msg1[32];
    int n1 = noise_handshake_write(&n->hs, NULL, 0, msg1, sizeof(msg1));
    if (n1 < 0) return -1;
    return ws_send_frame(w, WS_OP_BINARY, msg1, (size_t)n1);
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

int noise_ws_send(noise_ws_t *n, ws_t *w,
                  const uint8_t *pt, size_t pt_len) {
    if (!n->handshake_done) return -1;
    uint8_t ct[65 * 1024];
    if (pt_len + NOISE_TAG_LEN > sizeof(ct)) return -1;
    // Reserve TX space BEFORE encrypting: noise_transport_write burns a
    // nonce, so if ws_send_frame dropped the ciphertext afterwards the
    // send cipher would desync from the server and every later frame
    // would fail its auth tag ("Decrypt failed: invalid tag" → 4002).
    if (ws_ensure_tx_room(w, pt_len + NOISE_TAG_LEN) != 0) return -1;
    int cn = noise_transport_write(&n->transport, ct, sizeof(ct), pt, pt_len);
    if (cn < 0) return -1;
    return ws_send_frame(w, WS_OP_BINARY, ct, (size_t)cn);
}

void noise_ws_wipe(noise_ws_t *n) {
    noise_wipe(&n->hs, sizeof(n->hs));
    noise_wipe(&n->transport, sizeof(n->transport));
    memset(n, 0, sizeof(*n));
}
