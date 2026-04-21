// TCP + WebSocket + Noise_NX transport. See conn.h.
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE  // memmem

#include "conn.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "noise.h"
#include "util.h"

#define MAX_WS_FRAME   (1 << 20)   // 1 MiB — plenty for shell I/O

struct bridge_conn {
    int fd;
    noise_transport_t transport;

    // Buffered WS reader (holds partial frames across recv() calls)
    uint8_t *rx;
    size_t   rx_cap;
    size_t   rx_len;
};

// ── TCP ──────────────────────────────────────────────────────────────────────

static int tcp_connect(const char *host, uint16_t port) {
    char port_s[8];
    snprintf(port_s, sizeof(port_s), "%u", port);

    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_s, &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

// ── WS framing ───────────────────────────────────────────────────────────────

typedef enum {
    WS_OP_CONT  = 0x0,
    WS_OP_TEXT  = 0x1,
    WS_OP_BIN   = 0x2,
    WS_OP_CLOSE = 0x8,
    WS_OP_PING  = 0x9,
    WS_OP_PONG  = 0xA,
} ws_op_t;

// Encode client→server frame. buf must have cap ≥ len + 14.
static size_t ws_encode(uint8_t *buf, ws_op_t op,
                        const uint8_t *payload, size_t len) {
    size_t i = 0;
    buf[i++] = 0x80 | (uint8_t)op;  // FIN=1

    if (len < 126) {
        buf[i++] = 0x80 | (uint8_t)len;
    } else if (len <= 0xFFFF) {
        buf[i++] = 0x80 | 126;
        buf[i++] = (uint8_t)(len >> 8);
        buf[i++] = (uint8_t)(len & 0xFF);
    } else {
        buf[i++] = 0x80 | 127;
        for (int j = 0; j < 8; j++) buf[i++] = (uint8_t)((len >> (56 - j * 8)) & 0xFF);
    }

    uint8_t mask[4];
    if (noise_random(mask, 4) < 0) {
        // Mask integrity isn't security-critical (Noise provides real crypto).
        for (int j = 0; j < 4; j++) mask[j] = (uint8_t)(j * 37 + 1);
    }
    memcpy(buf + i, mask, 4);
    i += 4;
    for (size_t j = 0; j < len; j++) buf[i + j] = payload[j] ^ mask[j % 4];
    return i + len;
}

// Parse one server→client frame out of buf.
// Returns 1 on success (fields filled, *consumed set), 0 = need more, -1 = error.
static int ws_parse(const uint8_t *buf, size_t buf_len,
                    ws_op_t *op, const uint8_t **payload, size_t *payload_len,
                    size_t *consumed) {
    if (buf_len < 2) return 0;

    uint8_t b0 = buf[0], b1 = buf[1];
    uint8_t opc = b0 & 0x0F;
    if (!(b0 & 0x80)) return -1;           // no fragmentation support
    if (b1 & 0x80) return -1;              // server must not mask

    size_t len = b1 & 0x7F;
    size_t hdr = 2;
    if (len == 126) {
        if (buf_len < 4) return 0;
        len = ((size_t)buf[2] << 8) | buf[3];
        hdr = 4;
    } else if (len == 127) {
        if (buf_len < 10) return 0;
        len = 0;
        for (int i = 0; i < 8; i++) len = (len << 8) | buf[2 + i];
        hdr = 10;
    }
    if (len > MAX_WS_FRAME) return -1;
    if (buf_len < hdr + len) return 0;

    *op = (ws_op_t)opc;
    *payload = buf + hdr;
    *payload_len = len;
    *consumed = hdr + len;
    return 1;
}

// Send one WS frame.
static int ws_send(int fd, ws_op_t op, const uint8_t *payload, size_t len) {
    size_t cap = len + 14;
    uint8_t *buf = malloc(cap);
    if (!buf) return -1;
    size_t n = ws_encode(buf, op, payload, len);
    int rc = write_all(fd, buf, n);
    free(buf);
    return rc;
}

// Read bytes from fd into c->rx, extending as needed. Returns 0 or -1.
static int rx_read_more(bridge_conn_t *c) {
    if (c->rx_len == c->rx_cap) {
        size_t ncap = c->rx_cap * 2;
        if (ncap > MAX_WS_FRAME + 16) return -1;
        uint8_t *nb = realloc(c->rx, ncap);
        if (!nb) return -1;
        c->rx = nb;
        c->rx_cap = ncap;
    }
    ssize_t n = read(c->fd, c->rx + c->rx_len, c->rx_cap - c->rx_len);
    if (n <= 0) return -1;
    c->rx_len += (size_t)n;
    return 0;
}

// Read one WS frame (any opcode). Returns 1 on success (fills out*), 0=EOF, -1=err.
// Payload is copied into *out (caller provides buffer); *out_len set.
static int ws_recv(bridge_conn_t *c, ws_op_t *op, uint8_t *out, size_t out_cap,
                   size_t *out_len) {
    for (;;) {
        const uint8_t *pl;
        size_t pll, consumed;
        int r = ws_parse(c->rx, c->rx_len, op, &pl, &pll, &consumed);
        if (r < 0) return -1;
        if (r == 1) {
            if (pll > out_cap) return -1;
            memcpy(out, pl, pll);
            *out_len = pll;
            // Shift remaining bytes left
            size_t rem = c->rx_len - consumed;
            if (rem > 0) memmove(c->rx, c->rx + consumed, rem);
            c->rx_len = rem;
            return 1;
        }
        // Need more
        if (rx_read_more(c) != 0) return c->rx_len == 0 ? 0 : -1;
    }
}

// ── WebSocket handshake ──────────────────────────────────────────────────────

static int ws_handshake(int fd, const char *host, const char *path) {
    uint8_t nonce[16];
    if (noise_random(nonce, sizeof(nonce)) < 0) return -1;
    char key_b64[32];
    b64_encode(nonce, sizeof(nonce), key_b64);

    char req[1024];
    int rn = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        path, host, key_b64);
    if (rn < 0 || (size_t)rn >= sizeof(req)) return -1;
    if (write_all(fd, req, (size_t)rn) != 0) return -1;

    // Compute expected accept
    char accept_input[64];
    int alen = snprintf(accept_input, sizeof(accept_input),
                        "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key_b64);
    if (alen < 0 || (size_t)alen >= sizeof(accept_input)) return -1;
    uint8_t digest[20];
    sha1((const uint8_t *)accept_input, (size_t)alen, digest);
    char expected[32];
    b64_encode(digest, sizeof(digest), expected);

    // Read response until \r\n\r\n
    char buf[4096];
    size_t total = 0;
    while (total < sizeof(buf) - 1) {
        ssize_t n = read(fd, buf + total, sizeof(buf) - 1 - total);
        if (n <= 0) return -1;
        total += (size_t)n;
        if (memmem(buf, total, "\r\n\r\n", 4)) break;
    }
    buf[total < sizeof(buf) ? total : sizeof(buf) - 1] = '\0';

    if (total < 12 || memcmp(buf, "HTTP/1.1 101", 12) != 0) {
        const char *eol = memmem(buf, total, "\r\n", 2);
        size_t fl = eol ? (size_t)(eol - buf) : total;
        fprintf(stderr, "ws handshake failed: %.*s\n", (int)fl, buf);
        return -1;
    }

    // Check Sec-WebSocket-Accept (case-insensitive header, case-sensitive value)
    const char *p = strcasestr(buf, "sec-websocket-accept:");
    if (!p) return -1;
    p += strlen("sec-websocket-accept:");
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, expected, strlen(expected)) != 0) {
        fprintf(stderr, "ws accept mismatch\n");
        return -1;
    }
    return 0;
}

// ── Noise handshake ──────────────────────────────────────────────────────────

static int noise_do_handshake(bridge_conn_t *c, const uint8_t server_pubkey[32]) {
    noise_handshake_t hs;
    if (noise_handshake_init(&hs, server_pubkey) != 0) return -1;

    // msg1 initiator→responder: [e] (32 bytes)
    uint8_t msg1[32];
    int n1 = noise_handshake_write(&hs, NULL, 0, msg1, sizeof(msg1));
    if (n1 < 0) return -1;
    if (ws_send(c->fd, WS_OP_BIN, msg1, (size_t)n1) != 0) return -1;

    // msg2 responder→initiator: [e, ee, s, es] = 32 + 48 + 16 = 96 bytes (no payload)
    uint8_t frame[256];
    size_t frame_len;
    ws_op_t op;
    int r = ws_recv(c, &op, frame, sizeof(frame), &frame_len);
    if (r <= 0 || op != WS_OP_BIN) {
        fprintf(stderr, "noise handshake: expected binary reply\n");
        return -1;
    }
    uint8_t payload[64];
    int pn = noise_handshake_read(&hs, frame, frame_len, payload, sizeof(payload));
    if (pn < 0) {
        fprintf(stderr, "noise handshake verification failed\n");
        return -1;
    }

    if (noise_handshake_split(&hs, &c->transport) != 0) return -1;
    noise_wipe(&hs, sizeof(hs));
    return 0;
}

// ── Public API ───────────────────────────────────────────────────────────────

bridge_conn_t *bridge_conn_open(const char *host, uint16_t port,
                                const char *path,
                                const uint8_t server_pubkey[32]) {
    int fd = tcp_connect(host, port);
    if (fd < 0) { fprintf(stderr, "tcp connect failed\n"); return NULL; }

    if (ws_handshake(fd, host, path) != 0) { close(fd); return NULL; }

    bridge_conn_t *c = calloc(1, sizeof(*c));
    if (!c) { close(fd); return NULL; }
    c->fd = fd;
    c->rx_cap = 4096;
    c->rx = malloc(c->rx_cap);
    if (!c->rx) { free(c); close(fd); return NULL; }

    if (noise_do_handshake(c, server_pubkey) != 0) {
        bridge_conn_close(c);
        return NULL;
    }
    return c;
}

int bridge_conn_fd(bridge_conn_t *c) { return c->fd; }

long bridge_conn_recv(bridge_conn_t *c, uint8_t *out, size_t out_cap) {
    // Outer WS frame: ciphertext ≤ plaintext + 16 tag bytes. Allocate on stack for typical sizes.
    uint8_t frame[MAX_WS_FRAME];
    for (;;) {
        ws_op_t op;
        size_t flen;
        int r = ws_recv(c, &op, frame, sizeof(frame), &flen);
        if (r <= 0) return r == 0 ? 0 : -1;

        switch (op) {
            case WS_OP_BIN: {
                int pt = noise_transport_read(&c->transport, out, out_cap, frame, flen);
                if (pt < 0) return -1;
                return pt;
            }
            case WS_OP_PING:
                if (ws_send(c->fd, WS_OP_PONG, frame, flen) != 0) return -1;
                break;
            case WS_OP_CLOSE:
                return 0;
            default:
                // Ignore TEXT / CONT / unknown
                break;
        }
    }
}

int bridge_conn_send(bridge_conn_t *c, const uint8_t *msg, size_t len) {
    size_t cap = len + 16;  // Noise tag
    uint8_t *ct = malloc(cap);
    if (!ct) return -1;
    int cn = noise_transport_write(&c->transport, ct, cap, msg, len);
    if (cn < 0) { free(ct); return -1; }
    int rc = ws_send(c->fd, WS_OP_BIN, ct, (size_t)cn);
    free(ct);
    return rc;
}

void bridge_conn_close(bridge_conn_t *c) {
    if (!c) return;
    if (c->fd >= 0) close(c->fd);
    noise_wipe(&c->transport, sizeof(c->transport));
    free(c->rx);
    free(c);
}
