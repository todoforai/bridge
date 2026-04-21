// Base64 + SHA-1 — just enough for the WebSocket handshake and PTY I/O.
#include "util.h"
#include <string.h>

// ── Base64 ───────────────────────────────────────────────────────────────────

static const char B64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t b64_encode(const uint8_t *in, size_t in_len, char *out) {
    size_t i = 0, o = 0;
    while (i + 3 <= in_len) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[o++] = B64_ALPHABET[(v >> 18) & 0x3F];
        out[o++] = B64_ALPHABET[(v >> 12) & 0x3F];
        out[o++] = B64_ALPHABET[(v >>  6) & 0x3F];
        out[o++] = B64_ALPHABET[ v        & 0x3F];
        i += 3;
    }
    size_t rem = in_len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = B64_ALPHABET[(v >> 18) & 0x3F];
        out[o++] = B64_ALPHABET[(v >> 12) & 0x3F];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8);
        out[o++] = B64_ALPHABET[(v >> 18) & 0x3F];
        out[o++] = B64_ALPHABET[(v >> 12) & 0x3F];
        out[o++] = B64_ALPHABET[(v >>  6) & 0x3F];
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

long b64_decode(const char *in, size_t in_len, uint8_t *out) {
    // Strip trailing '='
    while (in_len > 0 && in[in_len - 1] == '=') in_len--;

    size_t o = 0;
    uint32_t v = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        int d = b64_val(c);
        if (d < 0) return -1;
        v = (v << 6) | (uint32_t)d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)((v >> bits) & 0xFF);
        }
    }
    return (long)o;
}

// ── SHA-1 (RFC 3174) ─────────────────────────────────────────────────────────

static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void sha1_block(uint32_t state[5], const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) |  (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 80; i++) {
        w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if      (i < 20) { f = (b & c) | (~b & d);            k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                     k = 0xCA62C1D6; }
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    uint32_t state[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    uint8_t block[64];
    size_t i = 0;

    while (len - i >= 64) {
        sha1_block(state, data + i);
        i += 64;
    }

    size_t rem = len - i;
    memcpy(block, data + i, rem);
    block[rem] = 0x80;

    if (rem >= 56) {
        memset(block + rem + 1, 0, 64 - rem - 1);
        sha1_block(state, block);
        memset(block, 0, 56);
    } else {
        memset(block + rem + 1, 0, 56 - rem - 1);
    }

    uint64_t bitlen = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++) block[56 + j] = (uint8_t)(bitlen >> (56 - j * 8));
    sha1_block(state, block);

    for (int j = 0; j < 5; j++) {
        out[j*4    ] = (uint8_t)(state[j] >> 24);
        out[j*4 + 1] = (uint8_t)(state[j] >> 16);
        out[j*4 + 2] = (uint8_t)(state[j] >>  8);
        out[j*4 + 3] = (uint8_t)(state[j]      );
    }
}
