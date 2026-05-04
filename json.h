// Tiny JSON accessor for control messages.
//
// Properly scans the top level of an object: skips strings (respecting \"),
// nested {} / [], and primitive values. So a `}` inside a string value or
// nested object can no longer end the search early.
//
// `json_str` returns a pointer/length into the source between the quotes —
// raw, NOT escape-decoded. That is intentional: protocol IDs are restricted
// to a safe charset (validated by the caller) and never legitimately contain
// `\`. For free-form text (paths, etc.) use `json_str_decoded`.
#ifndef BRIDGE_JSON_H
#define BRIDGE_JSON_H

#include <limits.h>
#include <stddef.h>
#include <string.h>

static inline const char *json__ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return p;
}

// Skip past one JSON string starting at *p == '"'. Returns position right
// after the closing quote, or NULL on malformed input.
static inline const char *json__skip_string(const char *p, const char *end) {
    if (p >= end || *p != '"') return NULL;
    p++;
    while (p < end) {
        if (*p == '\\') { if (p + 1 >= end) return NULL; p += 2; }
        else if (*p == '"') return p + 1;
        else p++;
    }
    return NULL;
}

// Skip past one JSON value (string/number/bool/null/object/array).
static inline const char *json__skip_value(const char *p, const char *end) {
    p = json__ws(p, end);
    if (p >= end) return NULL;
    if (*p == '"') return json__skip_string(p, end);
    if (*p == '{' || *p == '[') {
        char open = *p, close = (open == '{') ? '}' : ']';
        int depth = 1;
        p++;
        while (p < end && depth > 0) {
            if (*p == '"') { p = json__skip_string(p, end); if (!p) return NULL; }
            else if (*p == open)  { depth++; p++; }
            else if (*p == close) { depth--; p++; }
            else p++;
        }
        return depth == 0 ? p : NULL;
    }
    // Primitive: read until separator.
    while (p < end && *p != ',' && *p != '}' && *p != ']' &&
           *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
    return p;
}

// Find the value of `key` at the top level of the object in `data`. Returns
// pointer to the first byte of the value (whitespace already skipped), or NULL.
static inline const char *json__find(const char *data, size_t len, const char *key) {
    const char *p = data, *end = data + len;
    p = json__ws(p, end);
    if (p < end && *p == '{') p++;
    size_t klen = strlen(key);
    while (p < end) {
        p = json__ws(p, end);
        if (p >= end || *p == '}') return NULL;
        if (*p != '"') return NULL;
        const char *kstart = p + 1;
        const char *kend   = json__skip_string(p, end);
        if (!kend) return NULL;
        size_t cur_klen = (size_t)(kend - 1 - kstart);
        p = json__ws(kend, end);
        if (p >= end || *p != ':') return NULL;
        p = json__ws(p + 1, end);
        if (cur_klen == klen && memcmp(kstart, key, klen) == 0) return p;
        p = json__skip_value(p, end);
        if (!p) return NULL;
        p = json__ws(p, end);
        if (p < end && *p == ',') p++;
    }
    return NULL;
}

// Raw string value (between the quotes). Escape sequences are NOT decoded.
static inline int json_str(const char *data, size_t data_len,
                           const char *key,
                           const char **out, size_t *out_len) {
    const char *p = json__find(data, data_len, key);
    if (!p || *p != '"') return 0;
    const char *e = json__skip_string(p, data + data_len);
    if (!e) return 0;
    *out = p + 1;
    *out_len = (size_t)(e - 1 - (p + 1));
    return 1;
}

// Decoded string value: writes a NUL-terminated UTF-8 string into `out`.
// Handles \" \\ \/ \n \r \t \b \f \uXXXX (BMP only; surrogate pairs not joined).
// Returns 1 on success and sets *out_len; 0 on missing / overflow / bad escape.
static inline int json_str_decoded(const char *data, size_t data_len,
                                   const char *key,
                                   char *out, size_t out_cap, size_t *out_len) {
    const char *raw; size_t rlen;
    if (!json_str(data, data_len, key, &raw, &rlen)) return 0;
    size_t o = 0;
    for (size_t i = 0; i < rlen; i++) {
        if (o + 1 >= out_cap) return 0;
        char c = raw[i];
        if (c != '\\') { out[o++] = c; continue; }
        if (++i >= rlen) return 0;
        switch (raw[i]) {
            case '"':  out[o++] = '"';  break;
            case '\\': out[o++] = '\\'; break;
            case '/':  out[o++] = '/';  break;
            case 'n':  out[o++] = '\n'; break;
            case 'r':  out[o++] = '\r'; break;
            case 't':  out[o++] = '\t'; break;
            case 'b':  out[o++] = '\b'; break;
            case 'f':  out[o++] = '\f'; break;
            case 'u': {
                if (i + 4 >= rlen) return 0;
                unsigned cp = 0;
                for (int k = 0; k < 4; k++) {
                    char h = raw[i + 1 + k];
                    int v = (h >= '0' && h <= '9') ? h - '0' :
                            (h >= 'a' && h <= 'f') ? h - 'a' + 10 :
                            (h >= 'A' && h <= 'F') ? h - 'A' + 10 : -1;
                    if (v < 0) return 0;
                    cp = (cp << 4) | (unsigned)v;
                }
                i += 4;
                if (cp == 0) return 0;  // embedded NUL would truncate downstream C strings
                if (cp >= 0xD800 && cp <= 0xDFFF) return 0;  // unpaired surrogate
                if (cp < 0x80) {
                    if (o + 1 >= out_cap) return 0;
                    out[o++] = (char)cp;
                } else if (cp < 0x800) {
                    if (o + 2 >= out_cap) return 0;
                    out[o++] = (char)(0xC0 | (cp >> 6));
                    out[o++] = (char)(0x80 | (cp & 0x3F));
                } else {
                    if (o + 3 >= out_cap) return 0;
                    out[o++] = (char)(0xE0 | (cp >> 12));
                    out[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    out[o++] = (char)(0x80 | (cp & 0x3F));
                }
                break;
            }
            default: return 0;
        }
    }
    out[o] = '\0';
    *out_len = o;
    return 1;
}

// True if `c` ends a JSON value at the top level.
static inline int json__is_end(char c) {
    return c == ',' || c == '}' || c == ']' ||
           c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static inline int json_bool(const char *data, size_t data_len,
                            const char *key, int *out) {
    const char *p = json__find(data, data_len, key);
    if (!p) return 0;
    const char *end = data + data_len;
    if (p + 4 <= end && memcmp(p, "true", 4)  == 0 &&
        (p + 4 == end || json__is_end(p[4]))) { *out = 1; return 1; }
    if (p + 5 <= end && memcmp(p, "false", 5) == 0 &&
        (p + 5 == end || json__is_end(p[5]))) { *out = 0; return 1; }
    return 0;
}

static inline int json_int(const char *data, size_t data_len,
                           const char *key, long *out) {
    const char *p = json__find(data, data_len, key);
    if (!p) return 0;
    const char *end = data + data_len;
    int sign = 1;
    if (p < end && *p == '-') { sign = -1; p++; }
    unsigned long v = 0; int any = 0;
    // Cap at LONG_MAX magnitude (or LONG_MAX+1 for negatives) to avoid signed UB.
    const unsigned long limit = (sign < 0) ? (unsigned long)(-(long)(LONG_MIN + 1)) + 1ul
                                           : (unsigned long)LONG_MAX;
    while (p < end && *p >= '0' && *p <= '9') {
        unsigned d = (unsigned)(*p - '0');
        if (v > (limit - d) / 10) return 0;  // overflow
        v = v * 10 + d;
        p++; any = 1;
    }
    if (!any) return 0;
    if (p < end && !json__is_end(*p)) return 0;  // reject "1abc", "1.5", etc.
    *out = (sign < 0) ? -(long)v : (long)v;
    return 1;
}

#endif
