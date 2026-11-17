/* charset.c — same decision order as tfa-webfetch decodeBody: BOM, header charset, <meta charset> in the
 * first 4 KB, else UTF-8. Single-byte tables: latin1(=cp1252, per WHATWG), latin2, latin9, cp1250/1251/1252.
 * Unknown labels and invalid UTF-8 bytes → U+FFFD (as Node's toString does). */
#include "md.h"
#include "alloc.h"
#include "charset_tables.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

static size_t put(char *o, unsigned c) {
    if (c < 0x80) { o[0] = (char)c; return 1; }
    if (c < 0x800) { o[0] = (char)(0xC0 | c >> 6); o[1] = (char)(0x80 | (c & 63)); return 2; }
    if (c < 0x10000) { o[0] = (char)(0xE0 | c >> 12); o[1] = (char)(0x80 | (c >> 6 & 63)); o[2] = (char)(0x80 | (c & 63)); return 3; }
    o[0] = (char)(0xF0 | c >> 18); o[1] = (char)(0x80 | (c >> 12 & 63)); o[2] = (char)(0x80 | (c >> 6 & 63)); o[3] = (char)(0x80 | (c & 63)); return 4;
}
static int has_ci(const char *h, const char *n) {   /* portable strcasestr (mingw lacks it) */
    for (size_t l = strlen(n); *h; h++) if (!strncasecmp(h, n, l)) return 1;
    return 0;
}
static int find_label(const char *s, size_t n, char *lab) {  /* charset=... → lowercase label */
    for (size_t i = 0; i + 8 <= n; i++) if (!strncasecmp(s + i, "charset", 7)) {
        size_t j = i + 7; while (j < n && isspace((unsigned char)s[j])) j++;
        if (j >= n || s[j] != '=') continue;
        j++; while (j < n && (isspace((unsigned char)s[j]) || s[j] == '"' || s[j] == '\'')) j++;
        size_t k = 0; while (j < n && k < 31 && (isalnum((unsigned char)s[j]) || strchr("._:-", s[j]))) lab[k++] = (char)tolower((unsigned char)s[j++]);
        lab[k] = 0; return k > 0;
    }
    return 0;
}
static char *utf8_clean(const unsigned char *b, size_t n, size_t *ol) {  /* validate; bad bytes → U+FFFD */
    char *o = md_alloc(malloc(n * 3 + 1)), *w = o;
    for (size_t i = 0; i < n; ) {
        unsigned c = b[i]; size_t len = c && c < 0x80 ? 1 : c >= 0xC2 && c < 0xE0 ? 2 : c >= 0xE0 && c < 0xF0 ? 3 : c >= 0xF0 && c < 0xF5 ? 4 : 0;
        int ok = len && i + len <= n;
        for (size_t k = 1; ok && k < len; k++) ok = (b[i + k] & 0xC0) == 0x80;
        if (ok && len >= 3)
            ok = !(c == 0xe0 && b[i+1] < 0xa0) && !(c == 0xed && b[i+1] >= 0xa0)
              && !(c == 0xf0 && b[i+1] < 0x90) && !(c == 0xf4 && b[i+1] >= 0x90);
        if (ok) { memcpy(w, b + i, len); w += len; i += len; } else { w += put(w, 0xFFFD); i++; }
    }
    *w = 0; *ol = (size_t)(w - o); return o;
}
static char *utf16(const unsigned char *b, size_t n, int be, size_t *ol) {
    char *o = md_alloc(malloc(n * 2 + 4)), *w = o;
    for (size_t i = 0; i + 1 < n; i += 2) {
        unsigned c = be ? (unsigned)(b[i] << 8 | b[i + 1]) : (unsigned)(b[i + 1] << 8 | b[i]);
        if (c >= 0xD800 && c < 0xDC00 && i + 3 < n) { unsigned d = be ? (unsigned)(b[i + 2] << 8 | b[i + 3]) : (unsigned)(b[i + 3] << 8 | b[i + 2]);
            if (d >= 0xDC00 && d < 0xE000) { c = 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00); i += 2; } else c = 0xFFFD; }
        w += put(w, !c || (c >= 0xd800 && c < 0xe000) ? 0xfffd : c);
    }
    if (n % 2) w += put(w, 0xfffd);
    *w = 0; *ol = (size_t)(w - o); return o;
}

char *to_utf8(const unsigned char *b, size_t n, const char *ct, size_t *ol, const char **used) {
    if (n >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) { *used = "utf-8(bom)"; return utf8_clean(b + 3, n - 3, ol); }
    if (n >= 2 && b[0] == 0xFF && b[1] == 0xFE) { *used = "utf-16le"; return utf16(b + 2, n - 2, 0, ol); }
    if (n >= 2 && b[0] == 0xFE && b[1] == 0xFF) { *used = "utf-16be"; return utf16(b + 2, n - 2, 1, ol); }
    char lab[32] = "";
    if (!(ct && find_label(ct, strlen(ct), lab)) && (!ct || has_ci(ct, "html"))) {
        /* <meta ... charset=...> in the first 4 KB */
        size_t lim = n < 4096 ? n : 4096;
        for (size_t i = 0; i + 5 < lim; i++) if (b[i] == '<' && !strncasecmp((const char *)b + i, "<meta", 5)) {
            const unsigned char *gt = memchr(b + i, '>', lim - i);
            if (gt && find_label((const char *)b + i, (size_t)(gt - (b + i)), lab)) break;
        }
    }
    if (!strcmp(lab, "utf-16") || !strcmp(lab, "utf-16le") || !strcmp(lab, "utf-16be")) {
        int be = !strcmp(lab, "utf-16be"); *used = be ? "utf-16be" : "utf-16le";
        return utf16(b, n, be, ol);
    }
    char key[40]; snprintf(key, sizeof key, " %s ", lab);
    if (lab[0] && strcmp(lab, "utf-8") && strcmp(lab, "utf8"))
        for (size_t t = 0; t < sizeof SB / sizeof *SB; t++) if (strstr(SB[t].names, key)) {
            char *o = md_alloc(malloc(n * 3 + 1)), *w = o;
            for (size_t i = 0; i < n; i++) w += put(w, !b[i] ? 0xfffd : b[i] < 0x80 ? b[i] : SB[t].hi[b[i] - 0x80]);
            *w = 0; *ol = (size_t)(w - o); *used = SB[t].names + 1; return o;
        }
    *used = "utf-8"; return utf8_clean(b, n, ol);
}
