// Minimal JSON extraction for control messages.
// Only handles simple {"key":"value"} and {"key":123} patterns.
#ifndef BRIDGE_JSON_H
#define BRIDGE_JSON_H

#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Find "key":"value". On success, sets *out/len to point into data and returns 1.
static inline int json_str(const char *data, size_t data_len,
                           const char *key,
                           const char **out, size_t *out_len) {
    char needle[128];
    int nl = snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    if (nl <= 0 || (size_t)nl >= sizeof(needle)) return 0;
    if (data_len < (size_t)nl) return 0;

    for (size_t i = 0; i + (size_t)nl <= data_len; i++) {
        if (memcmp(data + i, needle, (size_t)nl) != 0) continue;
        size_t start = i + (size_t)nl;
        // find closing quote (no escape support — control protocol uses plain ids)
        for (size_t j = start; j < data_len; j++) {
            if (data[j] == '"') {
                *out = data + start;
                *out_len = j - start;
                return 1;
            }
        }
        return 0;
    }
    return 0;
}

// Find "key":N (integer). Returns 1 and sets *out on success.
static inline int json_int(const char *data, size_t data_len,
                           const char *key, long *out) {
    char needle[128];
    int nl = snprintf(needle, sizeof(needle), "\"%s\":", key);
    if (nl <= 0 || (size_t)nl >= sizeof(needle)) return 0;
    if (data_len < (size_t)nl) return 0;

    for (size_t i = 0; i + (size_t)nl <= data_len; i++) {
        if (memcmp(data + i, needle, (size_t)nl) != 0) continue;
        size_t start = i + (size_t)nl;
        // Skip optional sign + whitespace
        while (start < data_len && (data[start] == ' ' || data[start] == '\t')) start++;
        long val = 0;
        int sign = 1;
        if (start < data_len && data[start] == '-') { sign = -1; start++; }
        int any = 0;
        while (start < data_len && data[start] >= '0' && data[start] <= '9') {
            val = val * 10 + (data[start] - '0');
            start++;
            any = 1;
        }
        if (!any) return 0;
        *out = sign * val;
        return 1;
    }
    return 0;
}

#endif
