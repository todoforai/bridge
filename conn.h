// Bridge connection: TCP → WebSocket → Noise_NX transport.
//
// Exposes a plaintext message-oriented API to main.c. Under the hood:
//   1. plain TCP connect
//   2. WebSocket client handshake (no Bearer; auth happens inside Noise)
//   3. Noise_NX_25519_ChaChaPoly_BLAKE2b handshake as initiator (2 binary WS frames)
//   4. transport: each binary WS frame carries one Noise-encrypted JSON message
#ifndef BRIDGE_CONN_H
#define BRIDGE_CONN_H

#include <stddef.h>
#include <stdint.h>

typedef struct bridge_conn bridge_conn_t;

// Connect, WebSocket handshake, Noise handshake (in that order).
// server_pubkey is 32-byte X25519 static key of the server.
// Returns NULL on any failure (messages printed to stderr).
bridge_conn_t *bridge_conn_open(const char *host, uint16_t port,
                                const char *path,
                                const uint8_t server_pubkey[32]);

// Underlying fd for poll(). -1 if closed.
int bridge_conn_fd(bridge_conn_t *c);

// Read one plaintext message (after Noise decryption).
// Blocks until one full message is available, EOF, or error.
// Returns bytes written to out, 0 on close, -1 on error.
// Caller provides storage; messages larger than out_cap → -1.
long bridge_conn_recv(bridge_conn_t *c, uint8_t *out, size_t out_cap);

// Encrypt and send a plaintext message.
// Returns 0 on success, -1 on error.
int bridge_conn_send(bridge_conn_t *c, const uint8_t *msg, size_t len);

// Respond to a WS PING with PONG.  Internal use only; handled by recv().

void bridge_conn_close(bridge_conn_t *c);

#endif
