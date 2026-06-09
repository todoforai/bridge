// Scan server-pushed tool catalog: run versionCmd + statusCmd per tool,
// emit `{<key>:{installed,...}, ...}`. Triggered by `scan_tools`
// FUNCTION_CALL_REQUEST_AGENT (typically on connect).
#ifndef BRIDGE_TOOLS_H
#define BRIDGE_TOOLS_H

#include <stddef.h>

// Cap on the ", "-joined installedNow names (full list also in JSON reply).
#define BRIDGE_INSTALLED_NOW_CAP 512

typedef struct {
    int installed, authenticated, auth_applicable, installed_now;
    char installed_now_names[BRIDGE_INSTALLED_NOW_CAP];
} bridge_scan_stats_t;

// Parse "<key>\t<b64_versionCmd>\t<b64_statusCmd>\n..." into JSON in `out`.
// Returns length written, or -1 on overflow / fatal. `stats` may be NULL.
int bridge_scan_tools(const char *entries, size_t entries_len,
                      char *out, size_t out_cap,
                      bridge_scan_stats_t *stats);

#endif
