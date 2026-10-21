#ifndef BRIDGE_ENV_PATH_H
#define BRIDGE_ENV_PATH_H

// PATH helpers for HostDesktop-installed tools.

#ifdef _WIN32
void bridge_prepend_tools_path_win(void);
#else
// Caller frees the returned string.
char *bridge_build_tools_path(void);
// Write the askpass helper to ~/.todoforai/bin/askpass (0700, idempotent)
// and return its path, or NULL. Caller frees. See pty_posix.c for why.
char *bridge_ensure_askpass(void);
// Write the command shims (agent-browser-guard.sh → ~/.todoforai/bin/shims/
// agent-browser) and return that dir, or NULL. Caller frees. Prepended to
// PATH for agent shells only (pty_posix.c), not for the tool scan.
char *bridge_ensure_shims(void);
#endif

#endif
