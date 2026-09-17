# Plan: pre-warmed PTY shells for one-shot RUNs

## Problem

Every one-shot RUN (no `sessionId`) does `forkpty` + `exec sh` + init line before
the command can start. On Linux that is ~0.6 ms — invisible. On macOS `exec`
alone is 75–300 ms (dyld page-ins + code-signature checks; worse under load),
and an agent step spends 3–4 one-shot RUNs (command + file-change `pre`,
`stamp`, `post` snapshots) → ~1 s of pure spawn latency per step on an Intel
Mac. Windows ConPTY spawn is 50–100 ms, same shape.

Measured (MacBookPro14,3, load ~7, after reboot):

| | ms |
|---|---|
| `fork` only | 1.7 |
| `fork+exec /usr/bin/true` | 75–150 |
| `fork+exec /bin/sh -c exit` | 157–300 |
| cold spawn + run `echo` (bridge) | 166–390 |
| **prewarmed shell, run `echo`** | **0.4** |
| prewarmed + `cd` prefix | 0.6 |

## Idea

Keep a small pool of already-spawned, already-initialised shells parked at
their prompt, outside the session array. A one-shot RUN adopts one, prefixes
the wrapper with `cd -- '<cwd>' || exit 1;`, and runs. The pool refills in
the event loop, never on a RUN's critical path.

Only enabled where it pays: adaptive, by measuring the first cold spawn.

## Design — separate module `pty_pool.c/h`

All pool logic lives in its own translation unit, built on the public
`pty.h` API only (`bridge_pty_spawn/read/write_all/reap/close`). `main.c`
knows nothing about spares beyond three calls. Linked on every platform,
but decides at runtime whether it does anything (Linux → 0 spares, no
`#ifdef` forest).

### `pty_pool.h`

```c
// Pre-warmed one-shot shells. Zero-cost when target == 0.
void pty_pool_init(const char *init_line, size_t init_len);  // once, from main()
void pty_pool_note_cold_spawn(int64_t spawn_to_first_byte_ms); // adaptive enable
int  pty_pool_take(bridge_pty_t *out);   // 1 = adopted a ready spare, 0 = none
void pty_pool_service(int64_t now_ms);   // reap / readiness / refill (≤1 spawn per call)
void pty_pool_shutdown(void);            // SIGKILL + close all
```

`init_line` is the same string `build_init_line()` produces today (that
helper moves to `pty_pool.c`'s caller side — main passes it in, pool appends
its readiness marker). No shared globals, no session_t knowledge.

### `pty_pool.c` internals

```c
#define SPARE_MAX        5
#define SPARE_THRESHOLD  30      // ms; cold spawn slower than this → enable
#define SPARE_MAX_AGE_MS (10*60*1000)

typedef struct {
    bridge_pty_t pty;
    int64_t      spawned_ms;
    int          ready;        // marker seen
    char         rbuf[64];     // bytes read while waiting for the marker
    size_t       rlen;
} spare_t;

static spare_t g_spares[SPARE_MAX];
static int     g_target = -1;   // -1 undecided, 0 off, else SPARE_MAX
static char    g_init[128]; static size_t g_init_len;
```

- `pty_pool_init`: stores init line + `printf '\nSP''ARE_READY\n'` marker;
  honours `BRIDGE_SPARES=<n>` (sets `g_target` directly, skips adaptive).
- `pty_pool_note_cold_spawn`: if `g_target == -1`, decide
  `ms > SPARE_THRESHOLD ? SPARE_MAX : 0`, log once.
- `pty_pool_take`: first `ready` spare → copy pty out, zero the slot, return 1.
- `pty_pool_service`: for each live slot: `bridge_pty_reap` → dead/stale →
  close+clear; not-ready → non-blocking `bridge_pty_read` into `rbuf`, scan
  for marker → `ready=1`, discard bytes. Then if `live < g_target`, spawn
  **one** (`bridge_pty_spawn(&pty, NULL, NULL, 1)` + `write_all(init)`).
- `pty_pool_shutdown`: close all.

Spares are spawned like a cold one-shot (`no_echo=1`, default cwd via
`cwd=NULL`, same env/askpass/jail — all of that is already inside
`bridge_pty_spawn`, so the pool inherits it for free).

### `main.c` touch points (3)

1. `main()` after `spawn_env_init()`: `pty_pool_init(init_line, n)`.
   Event loop, after `service_sessions()`: `pty_pool_service(now)`.
   Exit path: `pty_pool_shutdown()`.
2. One-shot RUN branch, before `bridge_pty_spawn`:
   ```c
   int adopted = !s->cmd_mode && pty_pool_take(&s->pty);
   if (!adopted) { /* existing spawn + init line, unchanged */
       /* after first byte arrives: pty_pool_note_cold_spawn(dt) */ }
   ```
3. Wrapper build (POSIX branch): if `adopted`, prefix
   `cd -- '<cwd>' || exit 1;` (`'` escaped as `'\''`; cwd already validated).

`exit 1` on a vanished cwd kills the shell → reap → STEP_DONE code≠0, the
same outcome as the cold path's `INVALID_CWD`, slightly later.

Everything after (sentinels, `CANON_ON`, `draining_begin`, RUN_STARTED,
deadline, `run_finish` teardown) is untouched — an adopted shell is
indistinguishable from a cold one at its prompt.

### Platform behaviour

| platform | cold spawn | result |
|---|---|---|
| Linux | ~1 ms | adaptive → 0 spares; pool code idle (one `if` per tick) |
| macOS | 75–300 ms | 5 spares |
| Windows ConPTY (`pty_win.c`) | 50–100 ms | 5 spares; same code, `bridge_pty_*` abstracts it. cmd.exe mode never adopts (`cmd_mode` check) |

Override / test knob: `BRIDGE_SPARES=<n>` (0 disables).

### Shutdown / reconnect

- WS disconnect: spares stay (no backend state).
- Process exit: `pty_pool_shutdown()`.
- Policy reload (if/when it exists): call `pty_pool_shutdown()` so spares
  don't carry a stale jail/env; the 10 min age cap bounds it anyway.

## Sizing

Per agent step the *concurrent* need is ~3 (command + `pre` + `stamp` fire
together; `post` arrives after the command, by then refilled). Two agents on
one device peak at ~6 only if they step in the same instant. 5 spares cover
that in practice; overflow falls back to a cold spawn, never an error.

Cost of 5 idle `sh`: ~5 MB RSS, 5 ptys, 0 CPU.

## Non-goals

- Persistent (`sessionId`) sessions: untouched.
- cmd.exe mode: always cold (no `cd --`, different init).
- Pre-warming per cwd: `cd` is 0.2 ms, not worth pool fragmentation.

## Edge cases

| case | handling |
|---|---|
| spare shell dies while parked | reaped in `spares_service`, refilled |
| adopted shell's cwd vanished | `cd ‖ exit 1` → shell exits → STEP_DONE code≠0 |
| policy file changes at runtime | spares recycled at 10 min; policy reload should also `spares_drop_all()` |
| pool empty (burst) | cold spawn, exactly today's path |
| `evict_lru_idle` / `MAX_SESSIONS` | unaffected — spares live outside the array and don't count |
| `$PWD` differs from a fresh spawn | `cd --` sets `PWD`; `OLDPWD` = default cwd (harmless) |
| Windows | ConPTY spawn is also slow; pool works the same, `cd /d` prefix in cmd mode is out of scope |

## Tests

- `test/test_spare.c`: spawn pool with `BRIDGE_SPARES=2`, run 3 one-shot
  steps back-to-back → first two adopt (assert `from_spare`, cwd honoured via
  `pwd` output), third is cold; kill a spare externally → pool refills; cwd
  removed after adopt → step ends with code≠0.
- `test-timing` gains a `warm` column: spawn→first-byte with a ready spare
  must be < 5 ms on Linux.
- Existing suites (`test-run`, `test-park`, `test-runenv`, `test-initdrain`,
  `test-oneshot-leak`) must pass with `BRIDGE_SPARES=0` **and** `=5` —
  `test-oneshot-leak` in particular: adopted shells must be torn down by
  `run_finish` exactly like cold ones.

## Implementation steps

1. `pty_pool.c/h` (spawn/ready/reap/refill/shutdown, `BRIDGE_SPARES`), add
   to `COMMON_SRCS`, wire `init/service/shutdown` in `main.c` — no adoption
   yet. Run suites, confirm no behaviour change.
2. Adopt in the one-shot RUN branch + `cd --` prefix. `test_spare.c`
   (links `pty_pool.c` + `pty_posix.c` directly, no main.c needed for the
   pool-only cases).
3. `pty_pool_note_cold_spawn` from the first cold session's first byte.
4. Mac verification: `CC="clang -D_DARWIN_C_SOURCE" make test-timing` —
   expect `echo total` ≈ 1 ms instead of 166–390 ms; then a real agent step
   with file-change tracking on.

Estimated size: ~150 lines `pty_pool.c`, ~25 lines `pty_pool.h`, ~15 lines
changed in `main.c`, one test file. No wire-protocol or
backend change.
