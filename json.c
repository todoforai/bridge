#define _POSIX_C_SOURCE 200809L
#include "json.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

// ── Parser ──────────────────────────────────────────────────────────────────
// Recursive-descent skipper. We don't validate the whole document — we walk
// far enough to find the top-level key we want. Anything malformed past that
// is the sender's problem (and we'll just fail to find the key).

static const char *skip_ws(const char *p, const char *e) {
    while (p < e) {
        char c = *p;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') p++;
        else break;
    }
    return p;
}

// Skip over one JSON value starting at *p. Returns pointer past the value,
// or NULL on malformed input / end-of-buffer.
static const char *skip_value(const char *p, const char *e);

static const char *skip_string(const char *p, const char *e) {
    if (p >= e || *p != '"') return NULL;
    p++;
    while (p < e) {
        char c = *p++;
        if (c == '"') return p;
        if (c == '\\') {
            if (p >= e) return NULL;
            // 6-char unicode escape \uXXXX — skip the 4 hex digits.
            if (*p == 'u') {
                if (p + 5 > e) return NULL;
                p += 5;
            } else {
                p++;
            }
        }
    }
    return NULL;
}

static const char *skip_number(const char *p, const char *e) {
    if (p < e && (*p == '-' || *p == '+')) p++;
    while (p < e && (isdigit((unsigned char)*p) || *p == '.' ||
                     *p == 'e' || *p == 'E' || *p == '+' || *p == '-')) p++;
    return p;
}

static const char *skip_object(const char *p, const char *e) {
    if (p >= e || *p != '{') return NULL;
    p++;
    p = skip_ws(p, e);
    if (p < e && *p == '}') return p + 1;
    while (p < e) {
        p = skip_ws(p, e);
        p = skip_string(p, e);            // key
        if (!p) return NULL;
        p = skip_ws(p, e);
        if (p >= e || *p != ':') return NULL;
        p++;
        p = skip_ws(p, e);
        p = skip_value(p, e);
        if (!p) return NULL;
        p = skip_ws(p, e);
        if (p >= e) return NULL;
        if (*p == ',') { p++; continue; }
        if (*p == '}') return p + 1;
        return NULL;
    }
    return NULL;
}

static const char *skip_array(const char *p, const char *e) {
    if (p >= e || *p != '[') return NULL;
    p++;
    p = skip_ws(p, e);
    if (p < e && *p == ']') return p + 1;
    while (p < e) {
        p = skip_ws(p, e);
        p = skip_value(p, e);
        if (!p) return NULL;
        p = skip_ws(p, e);
        if (p >= e) return NULL;
        if (*p == ',') { p++; continue; }
        if (*p == ']') return p + 1;
        return NULL;
    }
    return NULL;
}

static const char *skip_value(const char *p, const char *e) {
    if (p >= e) return NULL;
    char c = *p;
    if (c == '"') return skip_string(p, e);
    if (c == '{') return skip_object(p, e);
    if (c == '[') return skip_array(p, e);
    if (c == 't' && e - p >= 4 && memcmp(p, "true",  4) == 0) return p + 4;
    if (c == 'f' && e - p >= 5 && memcmp(p, "false", 5) == 0) return p + 5;
    if (c == 'n' && e - p >= 4 && memcmp(p, "null",  4) == 0) return p + 4;
    if (c == '-' || (c >= '0' && c <= '9')) return skip_number(p, e);
    return NULL;
}

static int json_find(const char *buf, size_t len, const char *key,
                     json_type_t *type, const char **vp, size_t *vlen) {
    if (!buf || len == 0) return 0;
    const char *p = buf, *e = buf + len;
    p = skip_ws(p, e);
    if (p >= e || *p != '{') return 0;
    p++;
    size_t klen = strlen(key);

    while (p < e) {
        p = skip_ws(p, e);
        if (p >= e || *p == '}') return 0;
        // Read key (must be a string).
        if (*p != '"') return 0;
        const char *kstart = p + 1;
        const char *kend_q = skip_string(p, e);
        if (!kend_q) return 0;
        size_t found_klen = (size_t)(kend_q - 1 - kstart);
        p = kend_q;
        p = skip_ws(p, e);
        if (p >= e || *p != ':') return 0;
        p++;
        p = skip_ws(p, e);
        // Match? Compare raw bytes (keys with escapes won't match — we don't
        // emit escaped keys on the wire, so this is fine).
        int matched = (found_klen == klen && memcmp(kstart, key, klen) == 0);

        const char *vstart = p;
        json_type_t t = JT_NONE;
        if (p >= e) return 0;
        char c = *p;
        if (c == '"')                                  t = JT_STR;
        else if (c == '{')                             t = JT_OBJ;
        else if (c == '[')                             t = JT_ARR;
        else if (c == 't')                             t = JT_BOOL_T;
        else if (c == 'f')                             t = JT_BOOL_F;
        else if (c == 'n')                             t = JT_NULL;
        else if (c == '-' || (c >= '0' && c <= '9'))   t = JT_NUM;
        else return 0;
        const char *vend = skip_value(p, e);
        if (!vend) return 0;

        if (matched) {
            *type = t;
            if (t == JT_STR) {
                *vp = vstart + 1;                 // strip leading "
                *vlen = (size_t)(vend - vstart) - 2; // strip trailing "
            } else {
                *vp = vstart;
                *vlen = (size_t)(vend - vstart);
            }
            return 1;
        }
        p = vend;
        p = skip_ws(p, e);
        if (p >= e) return 0;
        if (*p == ',') { p++; continue; }
        if (*p == '}') return 0;
        return 0;
    }
    return 0;
}

int json_get_str(const char *buf, size_t len, const char *key,
                 const char **out, size_t *out_len) {
    json_type_t t;
    if (!json_find(buf, len, key, &t, out, out_len)) return 0;
    return t == JT_STR;
}

int json_get_obj(const char *buf, size_t len, const char *key,
                 const char **out, size_t *out_len) {
    json_type_t t;
    if (!json_find(buf, len, key, &t, out, out_len)) return 0;
    return t == JT_OBJ;
}

int json_obj_iter(const char *obj, size_t obj_len, size_t *pos,
                  const char **key, size_t *key_len,
                  const char **val, size_t *val_len, json_type_t *vtype) {
    const char *e = obj + obj_len;
    const char *p;
    if (*pos == 0) {
        p = skip_ws(obj, e);
        if (p >= e || *p != '{') return 0;
        p = skip_ws(p + 1, e);
        if (p < e && *p == '}') return 0;
    } else {
        p = skip_ws(obj + *pos, e);
        if (p >= e || *p != ',') return 0;  // '}' or malformed ⇒ done
        p = skip_ws(p + 1, e);
    }
    if (p >= e || *p != '"') return 0;
    const char *ks = p + 1;
    const char *kq = skip_string(p, e);
    if (!kq) return 0;
    *key = ks; *key_len = (size_t)(kq - 1 - ks);
    p = skip_ws(kq, e);
    if (p >= e || *p != ':') return 0;
    p = skip_ws(p + 1, e);
    if (p >= e) return 0;
    const char *vs = p;
    const char *ve = skip_value(p, e);
    if (!ve) return 0;
    char c = *vs;
    json_type_t t;
    if      (c == '"') t = JT_STR;
    else if (c == '{') t = JT_OBJ;
    else if (c == '[') t = JT_ARR;
    else if (c == 't') t = JT_BOOL_T;
    else if (c == 'f') t = JT_BOOL_F;
    else if (c == 'n') t = JT_NULL;
    else               t = JT_NUM;
    if (t == JT_STR) { *val = vs + 1; *val_len = (size_t)(ve - vs) - 2; }
    else             { *val = vs;     *val_len = (size_t)(ve - vs); }
    *vtype = t;
    *pos = (size_t)(ve - obj);
    return 1;
}

int json_get_bool(const char *buf, size_t len, const char *key, int *out) {
    json_type_t t; const char *vp; size_t vl;
    if (!json_find(buf, len, key, &t, &vp, &vl)) return 0;
    if (t == JT_BOOL_T) { *out = 1; return 1; }
    if (t == JT_BOOL_F) { *out = 0; return 1; }
    return 0;
}

int json_get_long(const char *buf, size_t len, const char *key, long *out) {
    json_type_t t; const char *vp; size_t vl;
    if (!json_find(buf, len, key, &t, &vp, &vl)) return 0;
    if (t != JT_NUM) return 0;
    char tmp[64];
    if (vl >= sizeof(tmp)) return 0;
    memcpy(tmp, vp, vl); tmp[vl] = '\0';
    char *endp = NULL;
    long v = strtol(tmp, &endp, 10);
    if (endp == tmp) return 0;
    *out = v;
    return 1;
}

static long json_unescape(const char *src, size_t src_len, char *dst, size_t dst_cap) {
    if (dst_cap == 0) return -1;
    size_t w = 0;
    for (size_t i = 0; i < src_len; i++) {
        if (w + 1 >= dst_cap) return -1;
        char c = src[i];
        if (c != '\\') { dst[w++] = c; continue; }
        if (++i >= src_len) return -1;
        char n = src[i];
        switch (n) {
            case '"':  dst[w++] = '"'; break;
            case '\\': dst[w++] = '\\'; break;
            case '/':  dst[w++] = '/'; break;
            case 'b':  dst[w++] = '\b'; break;
            case 'f':  dst[w++] = '\f'; break;
            case 'n':  dst[w++] = '\n'; break;
            case 'r':  dst[w++] = '\r'; break;
            case 't':  dst[w++] = '\t'; break;
            case 'u': {
                if (i + 4 >= src_len) return -1;
                unsigned cp = 0;
                for (int k = 1; k <= 4; k++) {
                    char h = src[i + k];
                    cp <<= 4;
                    if      (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                    else return -1;
                }
                i += 4;
                // Encode codepoint as UTF-8. (No surrogate pair handling —
                // our wire never emits non-BMP via \u.)
                if (cp < 0x80) {
                    if (w + 1 >= dst_cap) return -1;
                    dst[w++] = (char)cp;
                } else if (cp < 0x800) {
                    if (w + 2 >= dst_cap) return -1;
                    dst[w++] = (char)(0xC0 | (cp >> 6));
                    dst[w++] = (char)(0x80 | (cp & 0x3F));
                } else {
                    if (w + 3 >= dst_cap) return -1;
                    dst[w++] = (char)(0xE0 | (cp >> 12));
                    dst[w++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    dst[w++] = (char)(0x80 | (cp & 0x3F));
                }
                break;
            }
            default: return -1;
        }
    }
    dst[w] = '\0';
    return (long)w;
}

long json_unescape_span(const char *src, size_t src_len, char *dst, size_t dst_cap) {
    return json_unescape(src, src_len, dst, dst_cap);
}

int json_get_str_decoded(const char *buf, size_t len, const char *key,
                         char *dst, size_t cap, size_t *out_len) {
    const char *vp; size_t vl;
    if (!json_get_str(buf, len, key, &vp, &vl)) return 0;
    long n = json_unescape(vp, vl, dst, cap);
    if (n < 0) return 0;
    *out_len = (size_t)n;
    return 1;
}

// ── Writer ──────────────────────────────────────────────────────────────────

int json_emit_raw(char *out, size_t cap, size_t *used, const char *s, size_t s_len) {
    if (*used + s_len >= cap) return -1;
    memcpy(out + *used, s, s_len);
    *used += s_len;
    return 0;
}

int json_emit_str(char *out, size_t cap, size_t *used, const char *s, long s_len) {
    if (s_len < 0) s_len = (long)strlen(s);
    if (*used + 2 >= cap) return -1;
    out[(*used)++] = '"';
    for (long i = 0; i < s_len; i++) {
        unsigned char c = (unsigned char)s[i];
        const char *esc = NULL;
        char escbuf[8];
        size_t elen = 0;
        switch (c) {
            case '"':  esc = "\\\""; elen = 2; break;
            case '\\': esc = "\\\\"; elen = 2; break;
            case '\b': esc = "\\b";  elen = 2; break;
            case '\f': esc = "\\f";  elen = 2; break;
            case '\n': esc = "\\n";  elen = 2; break;
            case '\r': esc = "\\r";  elen = 2; break;
            case '\t': esc = "\\t";  elen = 2; break;
            default:
                if (c < 0x20) {
                    static const char H[] = "0123456789abcdef";
                    escbuf[0] = '\\'; escbuf[1] = 'u';
                    escbuf[2] = '0';  escbuf[3] = '0';
                    escbuf[4] = H[c >> 4];
                    escbuf[5] = H[c & 0xF];
                    esc = escbuf; elen = 6;
                }
        }
        if (esc) {
            if (*used + elen + 1 >= cap) return -1;
            memcpy(out + *used, esc, elen);
            *used += elen;
        } else {
            if (*used + 2 >= cap) return -1;
            out[(*used)++] = (char)c;
        }
    }
    if (*used + 1 >= cap) return -1;
    out[(*used)++] = '"';
    return 0;
}

// ── Base64 ──────────────────────────────────────────────────────────────────

static const char B64_E[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    size_t need = ((in_len + 2) / 3) * 4 + 1;
    if (out_cap < need) return 0;
    size_t o = 0;
    size_t i = 0;
    while (i + 3 <= in_len) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[o++] = B64_E[(v >> 18) & 0x3F];
        out[o++] = B64_E[(v >> 12) & 0x3F];
        out[o++] = B64_E[(v >>  6) & 0x3F];
        out[o++] = B64_E[ v        & 0x3F];
        i += 3;
    }
    if (i < in_len) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) v |= (uint32_t)in[i+1] << 8;
        out[o++] = B64_E[(v >> 18) & 0x3F];
        out[o++] = B64_E[(v >> 12) & 0x3F];
        out[o++] = (i + 1 < in_len) ? B64_E[(v >> 6) & 0x3F] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

static int b64_dec_one(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

size_t b64_decode(const char *in, size_t in_len, void *out, size_t out_cap) {
    uint8_t *o = (uint8_t *)out;
    size_t op = 0;
    int q[4]; int qn = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
        if (c == '=') break;
        int v = b64_dec_one(c);
        if (v < 0) return 0;
        q[qn++] = v;
        if (qn == 4) {
            if (op + 3 > out_cap) return 0;
            o[op++] = (uint8_t)((q[0] << 2) | (q[1] >> 4));
            o[op++] = (uint8_t)((q[1] << 4) | (q[2] >> 2));
            o[op++] = (uint8_t)((q[2] << 6) | q[3]);
            qn = 0;
        }
    }
    if (qn == 2) {
        if (op + 1 > out_cap) return 0;
        o[op++] = (uint8_t)((q[0] << 2) | (q[1] >> 4));
    } else if (qn == 3) {
        if (op + 2 > out_cap) return 0;
        o[op++] = (uint8_t)((q[0] << 2) | (q[1] >> 4));
        o[op++] = (uint8_t)((q[1] << 4) | (q[2] >> 2));
    } else if (qn != 0) {
        return 0;
    }
    return op;
}
