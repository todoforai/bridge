// Bridge self-update: startup binary swap.
//
// Server sends an `exec` that stages a new binary at `<exe>.new` (resolved
// via /proc/$PPID/exe — $PPID is the bridge, $0 is the shell) and kills the
// bridge. The supervisor restarts it; on startup we rename `<exe>.new` over
// `<exe>` (atomic on POSIX via rename(); Windows uses MoveFileEx with
// MOVEFILE_REPLACE_EXISTING — the running .exe lock is on content, not the
// directory entry).
#ifndef BRIDGE_UPDATE_H
#define BRIDGE_UPDATE_H

// Call once at process start, before anything else.
void bridge_update_swap_on_start(const char *argv0);

#endif
