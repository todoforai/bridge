// Bridge self-update: startup binary swap.
//
// Update mechanism: the server sends a normal `exec` command (shell) that
// downloads the new binary, verifies it, and stages it at `<exe>.new` —
// where <exe> is the bridge's own executable path, resolved via
// /proc/<PPID>/exe inside the shell (that PPID IS the bridge). Then the
// shell kills the bridge. A supervisor (systemd / launchd / shell loop)
// restarts it, and on startup the bridge resolves its own path and swaps
// `<exe>.new` into place before reconnecting.
//
// Example `exec` sent by the server (one chained shell command, && chained):
//
//   EXE=$(readlink -f /proc/$PPID/exe)
//   curl -fsSL https://dl.todofor.ai/bridge-linux-x64 -o "$EXE.tmp"
//   echo "<sha256>  $EXE.tmp" | sha256sum -c -
//   chmod +x "$EXE.tmp" && mv "$EXE.tmp" "$EXE.new"
//   kill -TERM $PPID
//
// Why $PPID and not $0: inside the shell spawned by bridge's `exec`, $0 is
// the shell itself (/bin/sh), not bridge. The bridge IS the parent process.
//
// POSIX only for now. `rename()` is atomic on the same filesystem; the
// staged file being a sibling of the target guarantees that. On Windows
// a running .exe cannot be renamed over, so the `.new` staging pattern
// is also what would be needed there (port TBD).
#ifndef BRIDGE_UPDATE_H
#define BRIDGE_UPDATE_H

// Resolve the bridge's own executable path (via /proc/self/exe on Linux,
// argv0 fallback elsewhere). If `<exe>.new` exists, rename it over <exe>.
// Silent no-op otherwise. Call once at process start, before anything else.
void bridge_update_swap_on_start(const char *argv0);

#endif
