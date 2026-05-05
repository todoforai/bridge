# TODOforAI Bridge

Native bridge runtime. Connects user machines, Firecracker sandboxes, and
cloud VMs to the TODOforAI backend over an encrypted WebSocket channel.

The same binary runs everywhere. Location is a deployment detail; the
protocol is uniform.

## Design principle

Bridges are **islands by default.** One guaranteed capability: "accept
commands from the backend over WebSocket and execute them." Everything
else — SSH, port exposure, overlay networking, language runtimes — is
configured by the AI at the user's request by running commands through
this same channel.

See [`../ARCHITECTURE_BRIDGE_MACHINES.md`](../ARCHITECTURE_BRIDGE_MACHINES.md)
for the overall model.

## Wire protocol

```
TCP → WebSocket → Noise_NX_25519_ChaChaPoly_BLAKE2b → JSON
```

No TLS. No OpenSSL. All crypto handled by Noise (monocypher + blake2b,
vendored in `noise/`).

After the Noise handshake, each binary WS frame carries one encrypted
JSON message. First encrypted message from edge is auth:

```json
{"type":"auth","deviceId":"dev_...","secret":"..."}
```

Device credentials are provisioned via `bridge login` (stored on disk by
the shared c-core login helper). Then the v2 multi-session protocol:
- `identity` (→ server, once)
- `exec` / `input` / `resize` / `signal` / `kill` (← server)
- `output` / `exit` / `error` (→ server)

Server side: `backend/src/api/ws/handlers/BridgeHandler.ts`.

## Layout

| File                  | Purpose                                              |
|-----------------------|------------------------------------------------------|
| `main.c`              | Event loop, session table, command dispatch         |
| `subcmd.c` / `.h`     | CLI subcommands: `login` / `enroll` / `whoami`      |
| `conn.c` / `conn.h`   | TCP + WS client handshake + Noise_NX initiator      |
| `util.c` / `util.h`   | Base64 + SHA-1 (for WS-Accept)                      |
| `pty.c` / `pty.h`     | `forkpty` session: read/write/resize/signal         |
| `identity.c` / `.h`   | Host identity gathering (`uname`, `pwd`, cwd)       |
| `tools.c` / `.h`      | Probe installed CLI tools, emit `installed_tools`   |
| `update.c` / `.h`     | Self-update: startup swap of staged `<exe>.new`     |
| `noise/`              | Vendored `noise.c` + `monocypher` (BLAKE2b)         |
| `mongoose/`           | Vendored `mongoose` (WS, JSON, base64, printf)      |

## Build

Only libc + `libutil` (for `forkpty`, in libc on macOS).

```sh
# Dynamic build (default system cc) — ~77 KB stripped, libc only
make
./build/bridge --help

# Static musl build via `zig cc` — ~90 KB, single-file, zero deps
make static

# Windows x64 build via `zig cc` (mingw-w64) — ~150 KB
make release-windows-x64
```

## Run

```sh
# First time: provision device credentials (opens browser / device flow)
./build/bridge login [--device-name NAME]

# Then connect — defaults to api.todofor.ai:80 (Noise is end-to-end;
# no TLS on the wire — typically Cloudflare/nginx terminates 443 in front)
./build/bridge

# Custom server
./build/bridge --host 127.0.0.1 --port 4000

# Via env
EDGE_HOST=... EDGE_PORT=... EDGE_SERVER_PUBKEY=... ./build/bridge

# Firecracker sandbox: presence of enroll.token=... in /proc/cmdline
# routes to DeviceType.SANDBOX path (?deviceType=SANDBOX).

# Show version / help
./build/bridge --version
./build/bridge --help
```

The server's Noise static public key (32 bytes, X25519, hex-encoded)
must match what the backend advertises at startup. Set via
`EDGE_SERVER_PUBKEY` or `--server-pubkey`. Default is baked into
`DEFAULT_SERVER_PUBKEY_HEX` in `main.c`.

## Updates

The bridge has no HTTP/download logic of its own. Updates ride on the
existing `exec` channel: the server sends a shell command that fetches
the new binary, verifies it, stages it next to the bridge as `<exe>.new`,
and kills the bridge. A supervisor (systemd / launchd / shell loop)
restarts it, and `update.c` swaps the staged binary in at startup (using
`/proc/self/exe` to resolve the real path).

Example `exec` payload the server sends — note `$PPID` (the bridge) is
the reliable way to find the executable; inside the shell, `$0` is the
shell itself:

```sh
EXE=$(readlink -f /proc/$PPID/exe) \
  && curl -fsSL https://github.com/todoforai/bridge/releases/latest/download/bridge-linux-x64 -o "$EXE.tmp" \
  && echo "<sha256>  $EXE.tmp" | sha256sum -c - \
  && chmod +x "$EXE.tmp" \
  && mv "$EXE.tmp" "$EXE.new" \
  && kill -TERM $PPID
```

No new protocol messages, no in-binary HTTP client, no extra dependencies.

## Notes

- POSIX + Windows (ConPTY, Win10 1809+). Windows build via
  `make release-windows-x64` (zig cc + mingw-w64). On Windows the bridge
  spawns `bash.exe` inside ConPTY — set `BRIDGE_SHELL` to override, otherwise
  it probes PATH then Git for Windows install paths, falling back to `cmd.exe`
  (RUN/tool catalog assume bash semantics — install Git for Windows or WSL).
  `step_paused` works on Linux, macOS, and Windows; on Windows the
  `passwordPrompt` flag is always 0 (the child's ECHO state isn't exposed
  through the ConPTY API).
- Session limit is 16 concurrent PTYs (`MAX_SESSIONS` in `main.c`).
- WebSocket uses plain `ws://` — TLS is replaced by Noise end-to-end.
  Typically deployed behind nginx/Cloudflare which terminates external
  TLS on 443 and forwards plain WS to the backend; the Noise channel
  runs through it unchanged.
