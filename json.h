// Minimal JSON parser + writer + base64. Parser handles flat top-level
// objects; nested object/array values are returned as raw byte spans for
// recursive json_get_* calls on the substring.
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

// Look up `key`; *out spans the raw value bytes (strings: excluding quotes,
// escapes still present). Returns 1 on found-and-string, 0 otherwise.
int json_get_str(const char *buf, size_t len, const char *key,
                 const char **out, size_t *out_len);

// Like json_get_str, but unescapes into dst[cap] and NUL-terminates.
int json_get_str_decoded(const char *buf, size_t len, const char *key,
                         char *dst, size_t cap, size_t *out_len);

// Value must be an object; *out spans `{...}` inclusive.
int json_get_obj(const char *buf, size_t len, const char *key,
                 const char **out, size_t *out_len);

int json_get_bool(const char *buf, size_t len, const char *key, int *out);
int json_get_long(const char *buf, size_t len, const char *key, long *out);

// Append a quoted, escaped string. `s_len = -1` ⇒ strlen(s). -1 on overflow.
int json_emit_str(char *out, size_t cap, size_t *used, const char *s, long s_len);

// Append raw pre-formatted bytes. -1 on overflow.
int json_emit_raw(char *out, size_t cap, size_t *used, const char *s, size_t s_len);

// Standard alphabet, no line wrapping. Encode NUL-terminates `out`.
// Decode returns 0 on invalid input.
size_t b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);
size_t b64_decode(const char *in, size_t in_len, void *out, size_t out_cap);

#endif
