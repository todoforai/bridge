// Keep-awake: while a task runs, stop the OS from going to sleep on idle.
// Opt-in (`keep_awake` in <config dir>/config.json, default off). Only system
// sleep is held — display sleep and screen lock are never touched — and the
// hold is dropped KEEP_AWAKE_GRACE_MS after the last task ends.
//
//   Linux:   `systemd-inhibit --what=sleep --mode=block cat` (logind)
//   macOS:   `caffeinate -i cat` (PreventUserIdleSystemSleep)
//   Windows: SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
//
// POSIX: the helper's stdin is a pipe only we hold, so when the bridge exits
// (even SIGKILL) `cat` sees EOF, exits, and the hold goes with it.
// Lid close on battery still sleeps (OS policy overrides inhibitors).
//
// config.json is NOT a security file: the backend may write it (the UI
// toggle), so it must never hold anything that widens access — that belongs
// in policy.json, which only a local actor writes.
#ifndef BRIDGE_KEEP_AWAKE_H
#define BRIDGE_KEEP_AWAKE_H

#include <stdint.h>

#define KEEP_AWAKE_GRACE_MS (2 * 60 * 1000)

// Pure idle timer (unit-tested): should the hold be up right now?
typedef struct { int64_t last_busy_ms; int held; } keep_awake_timer_t;
int keep_awake_want(keep_awake_timer_t *t, int enabled, int busy, int64_t now_ms);

// Read `keep_awake` from config.json (missing/broken file ⇒ off).
int keep_awake_load(void);
// Persist the setting. 0 on success.
int keep_awake_save(int enabled);

int keep_awake_enabled(void);
int keep_awake_active(void);

// UI/wire toggle: persist + apply. Returns 1 if reported state changed.
int keep_awake_set(int enabled);

// Call every loop tick with "≥1 task running". Re-reads config.json on each
// idle→busy edge (so `config keep-awake on|off` applies to the next task).
// Returns 1 when enabled/active changed (caller reports it).
int keep_awake_tick(int busy, int64_t now_ms);

// Drop the hold now (connection lost / shutdown). Returns 1 if it was held.
int keep_awake_release(void);

// {"type":"keep_awake_state","enabled":b,"active":b} — length or -1.
int keep_awake_state_json(char *out, unsigned cap);

// `todoforai-bridge config [keep-awake on|off]`
int cmd_config(int argc, char **argv);

#endif
