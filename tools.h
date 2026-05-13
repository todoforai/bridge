// Scan server-pushed tool catalog: run each tool's versionCmd + statusCmd,
// collect results, emit a JSON object keyed by tool name.
//
// Triggered by a `scan_tools` FUNCTION_CALL_REQUEST_AGENT (typically on
// connect). To refresh after install/uninstall the server can re-issue the call.
#ifndef BRIDGE_TOOLS_H
#define BRIDGE_TOOLS_H

#include <stddef.h>

typedef struct {
    int installed, authenticated;
} bridge_scan_stats_t;

// Full scan from the line-oriented payload of a TOOL_CATALOG message:
// "<key>\t<b64_versionCmd>\t<b64_statusCmd>\n...". Writes a JSON object
// `{<key>:{installed,...}, ...}` into `out` (up to out_cap bytes). Returns
// length written, or -1 on overflow / fatal error. If `stats` is non-NULL it
// is populated with per-scan counts.
int bridge_scan_tools(const char *entries, size_t entries_len,
                      char *out, size_t out_cap,
                      bridge_scan_stats_t *stats);

#endif
