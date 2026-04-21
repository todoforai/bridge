// Minimal crypto-free helpers: base64 + SHA-1 (for WS-Accept only).
#ifndef BRIDGE_UTIL_H
#define BRIDGE_UTIL_H

#include <stddef.h>
#include <stdint.h>

// Base64-encode in→out. out must have space for 4*((in_len+2)/3)+1 bytes (incl NUL).
// Returns chars written (excluding NUL).
size_t b64_encode(const uint8_t *in, size_t in_len, char *out);

// Base64-decode in→out. out must have space for (in_len/4)*3 bytes.
// Returns bytes written, or -1 on invalid input.
long b64_decode(const char *in, size_t in_len, uint8_t *out);

// SHA-1. out is 20 bytes.
void sha1(const uint8_t *data, size_t len, uint8_t out[20]);

#endif
