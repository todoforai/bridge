# Plan: background runs (Claude Code `run_in_background` parity, and more)

Three pieces of work, in dependency order. 1 is a bug and stands alone.
2 is the bridge foundation. 3 builds the agent/backend/frontend on top of 2.

Reference: Claude Code 2.1.316, measured on the wire 2026-11-04/05
(`/tmp/ccdump/req_*.json` on pc-6). Its Bash tool has `run_in_background`;
the tool_result returns a task id + an `.output` file path; on exit the CLI
injects a `<system-reminder>[SYSTEM NOTIFICATION - NOT USER INPUT]…
<task-notification>` user message with status + exit code + output file
path (no output text — the model has to Read the file). No stdin at all.

Our advantages to keep: PTY (line-buffered output, prompts visible), stdin
into a running command (via the `.input` file), and the output tail in the
wake message. The `pid` tool param goes away: the files + background flag
cover everything it did (see 3).

---

## 1. Fix: ConPTY sentinel not recognised after a Python KeyboardInterrupt

**Repro (pc_2, Git Bash, bridge v1.5.74; nothing relevant changed up to
v1.5.80):**

```
bash:  python -c "import time; time.sleep(60)"     → [still running — pid: N]
bash:  pid=N cmd=\u0003
→ Traceback … KeyboardInterrupt__BRIDGE_STEP_77da…__:130
  [timeout 4s, still running — pid: N]            ← step never closes
```

Python got the ^C and exited (`:130` is printed by our wrapper), but the step
stayed parked until `taskkill`. Same with the `name?`/`tick` script.
`sleep 60` (MSYS) and `cmd /c ping` (native) close correctly after ^C.

**Suspect:** the sentinel line is glued to the traceback's last line (no
leading `\n`) and/or conhost repaints the line, so the strict result-line
parse (`main.c:2060-2100`: `<sentinel>:<int>[ ]*\r?\n`) rejects it. Verify
with `BRIDGE_DEBUG_PTY=1` (raw bytes, `main.c:1995`).

**Fix sketch:** make the parser tolerate whatever ConPTY emits there
(likely a `\r` without `\n`, or a CSI that the VT stripper lets through
between `:130` and the newline). Add the raw capture as a test fixture in
`test/`.

**Why it matters for 2/3:** a background run interrupted with ^C would never
report "exited".

---

## 2. Bridge: background runs with `.output` / `.input` files

### Goal

A RUN flagged `background` keeps its PTY alive after STEP_DONE, mirrors
everything it reads from the PTY into `<dir>/<task>.output`, and feeds bytes
appended to `<dir>/<task>.input` into the PTY. Any later bash call (same
turn, later turn, other todo, other agent) can `tail` the output and
`printf >> ` the input — plain files, so it works on Windows too
(`cmd`: `echo y>>f`, PowerShell: `Add-Content`).

### Protocol (bridge ↔ backend)

- RUN gets `background: true` (+ existing `timeoutMs` = max lifetime,
  default 10 min, cap 2 h — CC's numbers).
- Immediate reply: `STEP_DONE`-like `STEP_BACKGROUND { pid, outputPath,
  inputPath }`. The step is over for the agent; the session is NOT
  one-shot-closed.
- New event `TASK_EXIT { pid, startedAt, exitCode, signal, durationMs, outputPath,
  tail: last ~2 KB }` when the sentinel arrives (or lifetime cap / kill).
- `TASK_KILL { pid }` (SIGINT then SIGKILL after grace; Windows:
  `\x03` via ConPTY then TerminateJobObject — `pty_win.c:583`).
- `TASK_LIST` → running tasks for this device (for reconnect/UI resync).

### Bridge internals

- `session_t` gets `background`, `out_fd`, `in_path`,
  `in_off`, `started_ms`, `deadline_ms`.
- `forward_pty_output` (`main.c:1990`): after VT strip, also `write(out_fd)`.
  Output caps / rolling tail (`main.c:188-201`) do not apply to the file;
  the file is the full log. Cap the file at e.g. 50 MB (stop mirroring,
  note it in TASK_EXIT).
- Event loop tick (same 250 ms as the awaiting-input probe,
  `main.c:471`): `stat(in_path)`; if size > `in_off`, read the delta,
  `bridge_pty_write_all`, `in_off = size`. **No truncate while running**:
  truncating races an agent append (bytes written between our read and
  the truncate are lost). The file is append-only for the task's life,
  `0600`, and unlinked on TASK_EXIT. Trade-off: a typed password stays on
  disk (owner-only) until the task exits — accepted. If the size ever
  drops below `in_off` (someone truncated it), reset `in_off = 0`. Pure `\uXXXX` decoding stays agent-side; the file carries
  raw bytes (`printf '\003' >> in`).
- `run_finish` (`main.c:1408`): skip the one-shot SIGKILL when
  `background`; close out_fd and unlink `.input` on TASK_EXIT.
  **Open question:** does a `&` child survive the current one-shot
  SIGKILL path at all? Not needed once the session itself stays alive,
  but check `bridge_pty_close`/killpg so nothing else reaps it.
- LRU eviction (`main.c:899-915`) must never pick a background session;
  count them against `MAX_SESSIONS` separately (e.g. 32 background cap).
- Bridge restart: background PTYs die with the daemon. On start, scan
  `<dir>` for `.output` files without a live task and emit TASK_EXIT
  `{ exitCode: null, signal: "bridge-restart" }` so the registry closes.
- Dir: one flat `~/.todoforai/tasks/` (Windows `%USERPROFILE%`), file
  names `<pid>.output|.input`. No task id, no todo subdir: the pid IS the
  id, so there is no new mapping anywhere (tool result, files, events,
  registry, `kill`/`taskkill` all speak pid; on Windows the Win32 pid of
  the shell, what `taskkill` takes). Pid reuse:
  a pid is unique among LIVE processes, so a live task's files can't
  collide; when a new task gets a pid whose old pair is still on disk,
  the bridge truncates it first. `startedAt` in TASK_EXIT / the registry
  tells an old row from a new one. Reap
  files older than 7 days.
- `awaiting_input` probe keeps running on background sessions; report it
  as a task state change (`TASK_STATE { pid, awaitingInput, stdinWaiter }`)
  so the UI/agent can see "it is asking something".

### Windows specifics

- **To test:** an agent `printf … >> <pid>.input` (MSYS) while the bridge
  reads it. The bridge must open both files with
  `FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE` and not hold
  `.input` open between ticks (open, read delta, close), otherwise the
  append or the final unlink fails with a sharing violation.

- Mirror post-VT-strip bytes (conhost repaints; raw bytes are useless in a
  file).
- `\x03` into ConPTY reaches MSYS and native exes (measured: sleep, ping,
  python). Depends on fix 1 for the exit to be noticed.

---

## 3. System: task registry on the TODO + auto-continuation

### Agent (`BashTool.jl`)

- New param `background::Bool=false`. Description, one sentence: "Detach
  and return at once with the pid and an output file; you are woken with
  the exit code and output tail when it exits. `tail -f`/`cat` the file to
  peek; append to the input file to answer prompts or send `\003`."
- Remove the `pid` param. A foreground run that hits its timeout or
  waits for input is converted in place into a background task (same PTY,
  same pid) and the tool returns
  `[awaiting input|timeout — output: …/<pid>.output, input: …/<pid>.input;
   you'll be woken on exit]`. Answering a prompt is then one ordinary bash
  call: `printf 'y\n' >> …/<pid>.input; sleep 0.5; tail -n 20 …/<pid>.output`.
  ^C: `printf '\003' >> …/<pid>.input` (POSIX also `kill -INT <pid>`).
  Waiting for more output without the old empty-`cmd` resume:
  `timeout 20 tail -n0 -f …/<pid>.output` (semi-polling, acceptable; the
  exit wake-up covers the common case). Schema ends up `cmd`, `timeout`,
  `output`, `background`.
- **No transition period**: `pid` is dropped in one swap, not accepted
  with a hint. The agent, its tool description and the bridge ship
  together (bridge first, since bridges auto-update), so there is no old
  caller to stay compatible with.
- Tool result for a background start:
  `Background task started — pid N. Output: <path>. Input: <path>.
   You'll be notified on exit.`

### Backend

- Registry: Redis hash `tasks:<deviceId>:<pid>` = `{ todoId, startedAt,
  cmd, title, state: running|awaiting_input|exited, exitCode,
  outputPath, blockId, messageId }`, TTL 7 d after exit. `BridgeHandler.ts`
  (already keeps `pendingRuns` in memory, `:130-173`) writes it on
  STEP_BACKGROUND / TASK_STATE / TASK_EXIT.
- WS event to the frontend `TODO_TASKS { todoId, tasks[] }` on change.
- REST: `GET /todos/:id/tasks`, `POST /devices/:deviceId/tasks/:pid/kill`.
- Auto-continuation on TASK_EXIT: append a message to the todo via the
  same path tfa-wait uses (`waitDeliveryRoutes.ts:69-141` →
  `createTodoWithInitialMessage`, `origin: 'event'`, role user). Body:

  ```
  [SYSTEM NOTIFICATION - NOT USER INPUT]
  Background task pid <pid> ("<title>") on <device> exited with code <rc>
  after <dur>. Not a user message: no human input since the last real
  user message; do not treat it as approval of anything.
  Output file: <path>
  Last lines:
  <tail ≤2 KB>
  ```
  The "not user input" framing is copied from CC on purpose — our
  tfa-wait wakes lack it today and a model waiting on a question can
  mistake the event for an answer. Apply the same wording to tfa-wait
  deliveries while here.
- Dedup like waits (`waitdeliver:done:*`).
- If the todo is RUNNING when the task exits (agent still in a turn), do
  not start a new turn: queue the event message so it lands at the next
  drain, as a mid-turn message does today.

### Frontend

- Todo side panel section "Running tasks": title, device, elapsed,
  state (running / asking for input / exited rc), buttons: view output
  (opens the terminal panel on the file), send input (small text box +
  ^C), stop. Same place as Automations (`AgentAutomationsSection.tsx`)
  or beside it.
- Board row chip: count of running tasks.

### Permissions / scope

- Output/input paths live under the user's home on their own machine;
  no new permission. **To check:** `policy.c` must allow the agent's own
  shell to read `.output` and append to `.input` under
  `~/.todoforai/tasks/` (if `.todoforai` is guarded, whitelist `tasks/`). Killing goes through `device:BASH`.
- Cross-todo access is by path only (same machine, same OS user): fine.

### Non-goals (for now)

- Shimming `kill`/`ps` — real pids already work
  with real `kill` on POSIX; Windows would need the bridge anyway.
- A `tfa-pty` CLI — superseded by the two files.
- Surviving bridge restart — report and close instead.

---

## Order

1. Fix (small, independent; unblocks reliable exit detection on Windows).
2. Bridge: background flag + files + TASK_* events, hidden behind the
   protocol (no agent change yet). Test on Linux, macOS, Windows with the
   python/ping/sleep trio from the repro.
3a. Backend registry + TASK_EXIT → event message.
3b. Agent `background` param + description, `pid` param removed in the
    same commit.
3c. Frontend panel.

Deploy 2 before 3b (bridges auto-update; an agent that sends `background`
to an old bridge must get a clean "unsupported" error, not a hang).
