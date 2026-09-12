// Local device policy: what the backend may reach on THIS machine.
//
// The backend is trusted for what to run, not for where. The policy file is
// written only by a local actor (`policy init|add`, the desktop app, or IT
// via /etc) — never by the wire — so a compromised backend or stolen device
// secret is confined to the listed workspaces.
//
// No policy file ⇒ inactive ⇒ today's behaviour (full user access).
// A policy file that can't be parsed or applied ⇒ fail closed: every path is
// denied and no shell spawns, with the reason on stderr at startup.
//
// Enforcement:
//   1. RUN cwd is prefix-checked; read/write_file open through
//      bridge_policy_open(), which on Linux resolves beneath the workspace
//      root (openat2 RESOLVE_BENEATH — symlink races can't escape).
//   2. Linux only: every process the backend can drive (PTY shell, tool-scan
//      worker) is Landlock-jailed at spawn — a few syscalls, then the kernel
//      mediates. macOS/Windows: (1) only; the shell itself is NOT confined.
//
// Invariant: the credentials/policy directory is never inside a workspace,
// so a jailed shell can't read the device secret or widen the policy.
// Toolchain dirs (~/.cache, ~/.local, ~/.cargo…) are writable inside the
// jail because installs need them — a poisoned tool there only affects
// jailed runs and the user's own later use of it. Documented tradeoff.
#ifndef BRIDGE_POLICY_H
#define BRIDGE_POLICY_H

#include <stddef.h>

#define POLICY_MAX_WS 32

typedef struct {
    int    active;                       // a policy file exists
    int    broken;                       // exists but unusable → deny all
    int    jail;                         // "jail": true (default)
    int    n;
    char   ws[POLICY_MAX_WS][1024];      // canonical absolute workspace roots
    char   path[1024];                   // file the policy came from
    char   err[256];                     // why broken
} bridge_policy_t;

extern bridge_policy_t g_policy;

// Load from /etc/todoforai/policy.json (wins) or the per-user config dir.
// Sets broken (never fails hard) — callers print g_policy.err.
void bridge_policy_load(void);

// 1 if `path` (absolute or ~-expanded) lies inside an allowed workspace, or
// the policy is inactive.
int bridge_policy_path_allowed(const char *path);

// Where a RUN lands when the backend sends no cwd: NULL when inactive
// (caller's default), else the first workspace.
const char *bridge_policy_default_cwd(void);

// open(2) honouring the policy: plain open when inactive; otherwise the
// path must be allowed and (Linux) is resolved beneath its workspace root so
// no symlink swapped in after the check can escape. -1/errno on failure
// (EACCES when the policy denies).
int bridge_policy_open(const char *path, int flags, int mode);

// Human-readable denial for the wire error: names the fix command.
const char *bridge_policy_deny_msg(const char *path, char *buf, size_t cap);

// In a child about to exec something the backend controls: confine it.
// 0 = done or nothing to do; -1 = refused (policy broken, or a jail was
// required but could not be applied) — caller must _exit, running
// unconfined would void the policy.
int bridge_policy_jail_child(void);

// `todoforai-bridge policy init|add PATH|list`
int cmd_policy(int argc, char **argv);

#endif
