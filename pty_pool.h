#ifndef BRIDGE_PTY_POOL_H
#define BRIDGE_PTY_POOL_H

// Pre-warmed one-shot shells.
//
// A one-shot RUN (no sessionId) normally pays forkpty+exec+shell-init before
// the command starts. On Linux that is ~1 ms; on macOS exec alone is 75–300 ms
// (dyld page-ins + code-signature checks, worse under load) and ConPTY spawn
// on Windows is 50–100 ms. An agent step issues 3–4 one-shots (command +
// file-change snapshots), so the spawn cost dominates the step on those OSes.
//
// The pool keeps up to PTY_POOL_MAX shells already spawned, initialised and
// parked at their (empty) prompt. RUN adopts one, prefixes its wrapper with a
// `cd`, and runs. Refill happens in the event loop, off the RUN's path.
//
// Self-measuring: pty_pool_init spawns one shell synchronously and times it
// to the readiness marker — under PTY_POOL_THRESHOLD_MS the pool switches
// itself off (Linux), so fast hosts pay one spawn at startup and nothing
// after. BRIDGE_SPARES=<n> overrides (0 = off). Built on the public pty.h
// API only.

#include <stddef.h>
#include <stdint.h>
#include "pty.h"

#define PTY_POOL_MAX          6
#define PTY_POOL_THRESHOLD_MS 30
#define PTY_POOL_MAX_AGE_MS   (10 * 60 * 1000)
#define PTY_POOL_PROBE_CAP_MS 2000

// `shell` as passed to bridge_pty_spawn (NULL = platform default). `init`
// is the same init line a cold one-shot receives (echo/prompt suppression);
// the pool appends its own readiness marker. Call once before the loop;
// blocks for one spawn (≤ PTY_POOL_PROBE_CAP_MS).
void pty_pool_init(const char *shell, const char *init, size_t init_len);

// Hand out a ready spare. Returns 1 and fills *out (caller owns the pty),
// 0 when none is ready (caller spawns cold). Never blocks.
int pty_pool_take(bridge_pty_t *out);

// Reap dead/stale spares, promote marker-seen spares to ready, spawn at most
// ONE replacement. Call every loop tick.
void pty_pool_service(int64_t now_ms);

// Kill + close every spare (process exit, policy reload).
void pty_pool_shutdown(void);

// POSIX wrapper prefix for an adopted shell: `cd -- '<cwd>' || exit 1; `
// (single quotes escaped). Returns bytes written, 0 if it doesn't fit.
size_t pty_pool_cd_prefix(const char *cwd, char *out, size_t cap);

// Introspection for tests/logging: 0 off, else target size.
int pty_pool_target(void);
int pty_pool_ready_count(void);

#endif
