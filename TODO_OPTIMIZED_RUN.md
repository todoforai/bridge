# TODO: optimized / noninteractive bridge RUN mode

Design and implement a first-class optimized run mode flag for todoforai-bridge shell execution.

## Context

Bridge RUN currently executes commands inside a PTY. That is useful for shell compatibility and prompt detection, but it makes many CLIs think a human is watching. Examples: `gh workflow list` and `git log` may open `less`, render spinners/progress, emit ANSI UI, or wait at `(END)`.

Temporary mitigation committed in `ef31c8f`:

- `PAGER=cat`
- `GH_PAGER=cat`
- `GIT_PAGER=cat`
- `MANPAGER=cat`
- `SYSTEMD_PAGER=cat`
- `AWS_PAGER=`

These are applied at PTY spawn and per RUN wrapper.

## Goal

Replace the ad-hoc defaults with an explicit run mode, e.g.

- `optimized: true` / `runMode: "optimized"`
- default for normal agent shell tool calls
- opt-out for truly interactive commands: REPLs, editors, password prompts, full-screen TUIs, etc.

## Things the optimized mode should control

- no pager:
  - `PAGER=cat`
  - `GH_PAGER=cat`
  - `GIT_PAGER=cat`
  - `MANPAGER=cat`
  - `SYSTEMD_PAGER=cat`
  - `AWS_PAGER=`
- less interactive/color UI where safe:
  - consider `NO_COLOR=1`, `CLICOLOR=0`, maybe `FORCE_COLOR=0`
  - careful: color can sometimes help readability, so make this configurable
- no spinners/progress where safe:
  - common CI/noninteractive env defaults
  - command-specific envs/flags where useful
- CI/noninteractive defaults:
  - consider `CI=1`
  - `DEBIAN_FRONTEND=noninteractive`
  - `GIT_TERMINAL_PROMPT=0` for noninteractive git/network commands
  - `PYTHONUNBUFFERED=1`
  - maybe `npm_config_yes=true` only when appropriate, not globally
- predictable terminal behavior:
  - fixed `COLUMNS`/`LINES`
  - fixed PTY winsize
  - maybe `TERM=dumb` in strict mode, but keep `xterm-256color` for compatibility unless tested
- faster output capture:
  - reduce ANSI noise
  - line-buffered output where possible
  - avoid alternate-screen/fullscreen modes
- protocol/API shape:
  - bridge RUN message should carry mode/options, not hardcoded forever
  - backend shell tool should default to optimized mode
  - frontend/agent can request interactive mode explicitly
- compatibility:
  - persistent sessions must not accidentally keep optimized env mutations when switching to interactive mode
  - shell startup files may override env; per-RUN wrapper should win for optimized mode
  - Windows ConPTY should avoid global process env mutation if possible; prefer explicit child environment block

## Acceptance criteria

- agent shell commands do not get stuck in pagers by default
- truly interactive commands can still run with a real TTY when requested
- behavior is documented in bridge README/protocol docs
- tests cover at least: gh/git pager suppression, opt-out interactive mode, persistent session mode switching
