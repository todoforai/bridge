#ifndef BRIDGE_ENV_PATH_H
#define BRIDGE_ENV_PATH_H

// PATH helpers for HostDesktop-installed tools.

#ifdef _WIN32
void bridge_prepend_tools_path_win(void);
#else
// Caller frees the returned string.
char *bridge_build_tools_path(void);
#endif

#endif
