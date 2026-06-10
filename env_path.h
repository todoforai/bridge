#ifndef BRIDGE_ENV_PATH_H
#define BRIDGE_ENV_PATH_H

// Shared helpers to make the bridge-managed tools binDir (~/.todoforai/tools/bin,
// mirroring the edge) discoverable, plus the legacy ~/.local/bin, across every
// command-execution path (scan_tools probes/installs and PTY sessions).

#ifdef _WIN32
// Prepend %USERPROFILE%\.todoforai\tools\bin to the bridge process PATH once.
// Children spawned with lpEnvironment=NULL inherit it. Idempotent; only marks
// itself done once PATH was successfully set.
void bridge_prepend_tools_path_win(void);
#else
// Build "<home>/.todoforai/tools/bin:<home>/.local/bin:<old PATH>" as a freshly
// malloc'd string (caller frees), or NULL on failure / missing $HOME. Intended
// to be called in a forked child right before exec, e.g.:
//     char *p = bridge_build_tools_path();
//     if (p) { setenv("PATH", p, 1); free(p); }
char *bridge_build_tools_path(void);
#endif

#endif
