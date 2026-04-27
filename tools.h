// Scan server-pushed tool catalog: run each tool's versionCmd + statusCmd,
// collect results, emit an `installed_tools` message.
//
// On Linux, also installs an inotify watcher on PATH directories that
// re-probes affected catalog entries when binaries appear/disappear,
// emitting delta `installed_tools` messages over the same callback.
#ifndef BRIDGE_TOOLS_H
#define BRIDGE_TOOLS_H

#include <stddef.h>

// Full scan from the line-oriented payload of a TOOL_CATALOG message:
// "<key>\t<b64_versionCmd>\t<b64_statusCmd>\n...". Writes a JSON
// `installed_tools` message into `out` (up to out_cap bytes). Returns length
// written, or -1 on overflow / fatal error.
int bridge_scan_tools(const char *entries, size_t entries_len,
                      char *out, size_t out_cap);

// Initialize the live PATH watcher. Caches the catalog so future PATH events
// can re-probe affected entries. The watcher does NOT send on the WS conn;
// instead it makes a delta JSON readable via the drain API below, so all
// network I/O stays on the main thread.
//
// Linux only. Returns 0 on success, -1 on fatal init failure. On non-Linux
// platforms returns 0 and does nothing (drain API also returns no data).
int bridge_tools_watch_init(const char *entries, size_t entries_len);

// Returns an fd that becomes readable when a delta is ready, or -1 if the
// watcher is not running. Add this to the main loop's poll set.
int bridge_tools_watch_eventfd(void);

// Drain at most one pending delta. If a delta is available, copies its JSON
// (NUL-terminated) into `out` and returns its length; else returns 0. Returns
// -1 on overflow (delta dropped). The buffer must be at least 64 KiB.
int bridge_tools_watch_drain(char *out, size_t out_cap);

// Stop the watcher and free state. Safe to call before/without init.
void bridge_tools_watch_stop(void);

#endif
