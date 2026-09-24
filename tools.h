// Scan server-pushed tool catalog: run versionCmd + statusCmd per tool,
// emit `{<key>:{installed,...}, ...}`. Triggered by `scan_tools`
// FUNCTION_CALL_REQUEST_AGENT (typically on connect).
#ifndef BRIDGE_TOOLS_H
#define BRIDGE_TOOLS_H

#include <stddef.h>

typedef struct {
    int installed, authenticated, auth_applicable;
} bridge_scan_stats_t;

// Parse "<key>\t<b64_versionCmd>\t<b64_statusCmd>\n..." into JSON in `out`.
// Returns length written, or -1 on overflow / fatal. `stats` may be NULL.
int bridge_scan_tools(const char *entries, size_t entries_len,
                      char *out, size_t out_cap,
                      bridge_scan_stats_t *stats);

// Write `arg` to `out` as ONE Windows command-line argument (not argv[0]),
// quoted per the MS C-runtime rules (MSYS/Git bash parses the same way):
// `"` → `\"`, backslashes doubled only before a `"` or the closing quote.
// Returns bytes written (excluding NUL), or -1 if it doesn't fit (then `out`
// may hold partial, unterminated output). Not for cmd.exe command lines.
// Pure string code, built on every platform so it is unit-tested on POSIX.
int bridge_win_quote_arg(const char *arg, char *out, size_t cap);

#endif
