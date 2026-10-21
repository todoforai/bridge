#!/bin/sh
# agent-browser guard (agent-browser-guard.sh) against a real headless Chrome:
# a session that connected to a CDP target must never fall back to
# agent-browser's own local browser. Run: make test-agent-browser-guard
# Needs agent-browser and google-chrome/chromium on PATH.
set -u
here=$(cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
mkdir "$tmp/bin"; cp "$here/agent-browser-guard.sh" "$tmp/bin/agent-browser"; chmod +x "$tmp/bin/agent-browser"
export PATH="$tmp/bin:$PATH" XDG_CACHE_HOME="$tmp/cache" AGENT_BROWSER_SESSION="guardtest$$" AGENT_BROWSER_SOCKET_DIR="$tmp/sock" TMPDIR="$tmp"
chrome_bin=$(command -v "${AGENT_BROWSER_EXECUTABLE_PATH:-}" || command -v google-chrome || command -v chromium || command -v chromium-browser) || { echo "SKIP: no chrome"; exit 0; }
port=$((20000 + $$ % 20000))
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "PASS: $1"; }
ko() { fail=$((fail + 1)); echo "FAIL: $1"; }
# agent-browser's own launches use --user-data-dir=$TMPDIR/agent-browser-chrome-<uuid>; a
# per-test TMPDIR counts only ours (other agents may run their own), orphans included.
local_chromes() { pgrep -fc "user-data-dir=$TMPDIR/agent-browser-chrome-" || true; }
start_chrome() { "$chrome_bin" --headless=new --no-sandbox --remote-debugging-port=$port --user-data-dir="$tmp/prof" about:blank >/dev/null 2>&1 & chrome=$!; sleep 2; }
cleanup() { agent-browser close >/dev/null 2>&1; kill "$chrome" 2>/dev/null; wait "$chrome" 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT

base=$(local_chromes)
start_chrome
out=$(agent-browser connect $port 2>&1) && echo "$out" | grep -q 'match=yes' && ok "connect + whoami" || ko "connect: $out"
agent-browser open 'data:text/html,<title>guard</title>' >/dev/null 2>&1 && [ "$(agent-browser get title)" = guard ] && ok "happy path" || ko "happy path"

# Launch-ish env (the cloud image sets this) used to flip the session to a local launch.
AGENT_BROWSER_EXECUTABLE_PATH="$chrome_bin" agent-browser get cdp-url 2>&1 | grep -q ":$port/" && ok "AGENT_BROWSER_EXECUTABLE_PATH keeps the attach" || ko "executable-path flipped the session"

kill "$chrome"; wait "$chrome" 2>/dev/null
out=$(agent-browser open https://example.com 2>&1); rc=$?
[ $rc -ne 0 ] && echo "$out" | grep -q 'NOT falling back' && ok "lost browser: command fails loudly" || ko "lost browser: rc=$rc $out"
out=$(agent-browser whoami 2>&1) && ko "whoami after loss succeeded: $out" || ok "whoami reports DISCONNECTED"
[ "$(local_chromes)" = "$base" ] && ok "no local Chrome launched" || ko "agent-browser launched its own Chrome"

# Daemon restart (idle timeout) used to forget the target and launch locally.
start_chrome
agent-browser connect $port >/dev/null 2>&1
pid=$(cat "$AGENT_BROWSER_SOCKET_DIR/$AGENT_BROWSER_SESSION.pid")
kill "$pid"; i=0; while [ -e "$AGENT_BROWSER_SOCKET_DIR/$AGENT_BROWSER_SESSION.sock" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
agent-browser get cdp-url 2>&1 | grep -q ":$port/" && ok "daemon restart reattaches to the same browser" || ko "daemon restart lost the target"
[ "$(local_chromes)" = "$base" ] && ok "still no local Chrome" || ko "local Chrome after daemon restart"

# Review cases: explicit --session, --auto-connect false, close under a launch-ish env, odd names.
s2="guard2$$"
agent-browser --session "$s2" connect $port 2>&1 | grep -q "session=$s2 browser=cdp match=yes" && ok "--session flag: connect verifies that session" || ko "--session flag"
agent-browser --session "$s2" --auto-connect false get cdp-url 2>&1 | grep -q ":$port/" && ok "--auto-connect false stays pinned" || ko "--auto-connect false bypassed the pin"
AGENT_BROWSER_EXECUTABLE_PATH="$chrome_bin" agent-browser --session "$s2" close >/dev/null 2>&1
[ "$(local_chromes)" = "$base" ] && ok "close under AGENT_BROWSER_EXECUTABLE_PATH launches nothing" || ko "close launched a local Chrome"
agent-browser --session 'a/b' get url >/dev/null 2>&1; [ $? -eq 2 ] && ok "unsafe session name refused" || ko "unsafe session name ran"
out=$(agent-browser connect "ws://127.0.0.1:1/ws/v2/cdp?token=SECRET123" 2>&1; agent-browser whoami 2>&1)
case $out in *SECRET123*) ko "token leaked: $out";; *) ok "failed connect + whoami never print the token";; esac
agent-browser close >/dev/null 2>&1

# A browser that accepts the socket but never answers must not hang connect.
bun -e 'Bun.serve({port:'$((port + 1))',fetch(r,s){return s.upgrade(r)?undefined:new Response("")},websocket:{message(){}}})' >/dev/null 2>&1 & mute=$!
sleep 1; t0=$(date +%s)
out=$(AGENT_BROWSER_CONNECT_TIMEOUT=5 timeout 60 agent-browser connect "ws://127.0.0.1:$((port + 1))/" 2>&1); rc=$?
if [ $rc -eq 124 ] && [ $(( $(date +%s) - t0 )) -lt 30 ]; then ok "connect to a silent browser fails in bounded time"; else ko "connect hung or succeeded: rc=$rc $out"; fi
# (ps state Z: a killed daemon stays a zombie until reaped, e.g. under a non-reaping pid 1)
dp=$(cat "$AGENT_BROWSER_SOCKET_DIR/$AGENT_BROWSER_SESSION.pid" 2>/dev/null)
[ -n "$dp" ] && ps -o stat= -p "$dp" 2>/dev/null | grep -qv Z && ko "hung daemon left running" || ok "hung daemon stopped"
[ "$(local_chromes)" = "$base" ] && ok "silent browser: no local Chrome" || ko "silent browser: local Chrome launched"
kill $mute; agent-browser close >/dev/null 2>&1

# A session already driving agent-browser's own Chrome must not keep it when first pinned via --cdp.
start_chrome
s3="guard3$$"
real=$(PATH=${PATH#"$tmp/bin:"} command -v agent-browser)
AGENT_BROWSER_EXECUTABLE_PATH="$chrome_bin" "$real" --session "$s3" open about:blank >/dev/null 2>&1
agent-browser --session "$s3" --cdp $port get cdp-url 2>&1 | grep -q ":$port/" && ok "first --cdp replaces an unpinned local daemon" || ko "first --cdp kept the local browser"
agent-browser --session "$s3" close >/dev/null 2>&1; sleep 1
[ "$(local_chromes)" = "$base" ] && ok "local Chrome of the replaced daemon is gone" || ko "replaced daemon's local Chrome still running"

echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
