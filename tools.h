// Scan server-pushed tool catalog: run each tool's versionCmd + statusCmd,
// collect results, emit an `installed_tools` message.
//
// Runs once per `tool_catalog` message (typically on connect). To refresh
// after install/uninstall the server can re-send the catalog.
#ifndef BRIDGE_TOOLS_H
#define BRIDGE_TOOLS_H

#include <stddef.h>

// Full scan from the line-oriented payload of a TOOL_CATALOG message:
// "<key>\t<b64_versionCmd>\t<b64_statusCmd>\n...". Writes a JSON
// `installed_tools` message into `out` (up to out_cap bytes). Returns length
// written, or -1 on overflow / fatal error.
int bridge_scan_tools(const char *entries, size_t entries_len,
                      char *out, size_t out_cap);

#endif
