// Minimal JSON parser + writer + base64 — sized exactly to the bridge's needs.
//
// Parser scope: flat objects only (our wire protocol is `{key:value, ...}`
// with no nested control structures we care to read). Nested objects/arrays
// can appear as values; we return their raw byte range so the caller can
// recurse with json_find again on the substring.
//
// Writer scope: build JSON strings into a fixed buffer with proper escaping
// for `"`, `\`, control bytes (\b\f\n\r\t and \u00xx for the rest <0x20).
//
// Base64: standard alphabet, no line wrapping.
#ifndef BRIDGE_JSON_H
#define BRIDGE_JSON_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    JT_NONE  = 0,
    JT_STR,
    JT_NUM,
    JT_BOOL_T,
    JT_BOOL_F,
    JT_NULL,
    JT_OBJ,
    JT_ARR
} json_type_t;

// Find `key` in the top-level object `buf[len]`. On match, *type/*vp/*vlen
// describe the value. For strings, *vp/*vlen exclude the surrounding quotes
// and may still contain JSON escapes — call json_unescape if you need the
// decoded text. Returns 1 on found, 0 otherwise.
int json_find(const char *buf, size_t len, const char *key,
              json_type_t *type, const char **vp, size_t *vlen);

// Convenience: like json_find but only succeeds if the value is a string.
int json_get_str(const char *buf, size_t len, const char *key,
                 const char **out, size_t *out_len);

// Like json_get_str but also unescapes the value into `dst[cap]`. Returns 1
// on success (and sets *out_len), 0 on missing/wrong-type/overflow.
int json_get_str_decoded(const char *buf, size_t len, const char *key,
                         char *dst, size_t cap, size_t *out_len);

int json_get_bool(const char *buf, size_t len, const char *key, int *out);
int json_get_long(const char *buf, size_t len, const char *key, long *out);

// Decode JSON string escapes from src into dst. NUL-terminates dst.
// Returns bytes written, or -1 on overflow / malformed escape.
long json_unescape(const char *src, size_t src_len, char *dst, size_t dst_cap);

// Append a fully-quoted, JSON-escaped string into out at *used. `s_len = -1`
// means strlen(s). Returns 0 on success, -1 on overflow.
int json_emit_str(char *out, size_t cap, size_t *used, const char *s, long s_len);

// Append raw bytes (already JSON-formatted) at *used. -1 on overflow.
int json_emit_raw(char *out, size_t cap, size_t *used, const char *s, size_t s_len);

// Append a printf-style fragment at *used. Returns 0 / -1.
int json_emit_fmt(char *out, size_t cap, size_t *used, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

// Base64 encode / decode (standard alphabet). Encode NUL-terminates `out`
// and returns bytes written (excluding NUL). Decode returns bytes written;
// returns 0 on invalid input.
size_t b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);
size_t b64_decode(const char *in, size_t in_len, void *out, size_t out_cap);

#endif
