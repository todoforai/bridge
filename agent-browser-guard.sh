#!/bin/sh
# TODOFORAI_AGENT_BROWSER_GUARD: written by todoforai-bridge; edits are overwritten.
#
# agent-browser (<= 0.39.1) forgets the browser it was `connect`ed to when the
# CDP socket drops, when its daemon restarts (idle timeout), or when a launch
# option (AGENT_BROWSER_EXECUTABLE_PATH) is set, and then silently launches its
# OWN headless Chrome: the agent keeps working in a browser nobody can see.
# This guard pins each session to the target it connected to and passes
# `--session <s> --cdp <target>` on every call, so a lost browser is an error
# (or a reconnect to the SAME browser), never a local fallback.
# `agent-browser whoami` reports which browser the session is driving.
set -f
unset AGENT_BROWSER_JSON   # internal probes parse plain text; --json still works per call

me=$(cd -- "$(dirname -- "$0")" && pwd)
real=
IFS=:
for d in $PATH; do
  [ -n "$d" ] && [ "$d" != "$me" ] && [ -f "$d/agent-browser" ] && [ -x "$d/agent-browser" ] || continue
  head -c 256 "$d/agent-browser" 2>/dev/null | grep -q TODOFORAI_AGENT_BROWSER_GUARD && continue
  real=$d/agent-browser; break
done
unset IFS
[ -n "$real" ] || { echo "agent-browser: not installed" >&2; exit 127; }
die() { echo "agent-browser: $*" >&2; exit 2; }

# Global flags (agent-browser flags.rs); value flags consume the next word.
sess=${AGENT_BROWSER_SESSION:-default}; cmd=; arg1=; flag_cdp=; other=; info=; all=; skip=
for a do
  case $skip in
    session) sess=$a; skip=; continue;;
    cdp) flag_cdp=$a; skip=; continue;;
    auto) skip=; case $a in false) continue;; true) other=1; continue;; esac; other=1;;
    value) skip=; continue;;
    bool) skip=; case $a in true|false) continue;; esac;;
  esac
  case $a in
    --session) skip=session;;
    --cdp) skip=cdp;;
    --auto-connect) skip=auto;;
    -p|--provider) skip=value; other=1;;
    --headers|--executable-path|--extension|--init-script|--enable|--profile|--state|--proxy|--proxy-bypass|\
    --args|--user-agent|--device|--session-name|--color-scheme|--download-path|--max-output|--allowed-domains|\
    --action-policy|--confirm-actions|--config|--engine|--screenshot-dir|--screenshot-quality|\
    --screenshot-format|--idle-timeout|--model) skip=value;;
    --json|--headed|--debug|--ignore-https-errors|--allow-file-access|--hide-scrollbars|--annotate|\
    --content-boundaries|--confirm-interactive|--no-auto-dialog) skip=bool;;
    -h|--help|-V|--version) info=1;;
    --all) all=1;;
    -*) ;;
    *) if [ -z "$cmd" ]; then cmd=$a; elif [ -z "$arg1" ]; then arg1=$a; fi;;
  esac
done
[ -n "$info" ] && exec "$real" "$@"
case $cmd in ''|session|install|upgrade|doctor|skills|help|dashboard) exec "$real" "$@";; esac

case $sess in *[!A-Za-z0-9._-]*|.*) die "session name '$sess' must match [A-Za-z0-9._-]+";; esac
pin_dir=${XDG_CACHE_HOME:-$HOME/.cache}/todoforai/agent-browser
pin=$pin_dir/$sess.cdp
target=$(cat "$pin" 2>/dev/null)
save() {
  mkdir -p "$pin_dir" && (umask 077 && printf '%s\n' "$1" >"$pin.$$" && mv -f "$pin.$$" "$pin") \
    || die "cannot record the connected browser in $pin; refusing to run unguarded"
  target=$1
}
kind() {
  case $1 in
    *"/ws/v2/cdp?token=e."*) echo embedded;;
    *"/ws/v2/cdp?token="*) echo extension;;
    '') echo local;;
    *) echo cdp;;
  esac
}
redact() { sed 's/token=[^&[:space:]"'\'']*/token=***/g'; }
# This session's daemon pid: alive, agent-browser, and (where /proc shows it) serving this session.
sock_dir=${AGENT_BROWSER_SOCKET_DIR:-${XDG_RUNTIME_DIR:+$XDG_RUNTIME_DIR/agent-browser}}
sock_dir=${sock_dir:-$HOME/.agent-browser}
daemon_pid() {
  p=$(cat "$sock_dir/$sess.pid" 2>/dev/null) && [ -n "$p" ] && ps -p "$p" -o args= 2>/dev/null | grep -q agent-browser || return 1
  [ -r "/proc/$p/environ" ] && ! tr '\0' '\n' <"/proc/$p/environ" | grep -qx "AGENT_BROWSER_SESSION=$sess" && return 1
  echo "$p"
}
# Stop the daemon; a hung one ignores SIGTERM (it handles it under the lock the hung command holds).
stop_daemon() {
  p=$(daemon_pid) || return 0
  kill "$p" 2>/dev/null; i=0
  while kill -0 "$p" 2>/dev/null && [ $i -lt 30 ]; do sleep 0.1; i=$((i + 1)); done
  [ "$(daemon_pid)" = "$p" ] && kill -9 "$p" 2>/dev/null; return 0
}
# A pinned agent-browser call; "$@" = its subcommand and args.
ab() { "$real" --session "$sess" ${target:+--cdp "$target"} "$@" 9>&-; }   # 9 = lock; a spawned daemon must not hold it
# bounded SECS ab ARGS...: after SECS (0 = no limit) kill the CLI and the session daemon
# (a hung daemon hangs every later call too) and return 124. Runs the real binary
# directly (not the ab function) so the kill reaches it.
bounded() {
  t=$1; shift 2
  [ "$t" -gt 0 ] 2>/dev/null || { ab "$@"; return; }
  m=$(mktemp "${TMPDIR:-/tmp}/ab-guard.XXXXXX") && rm -f "$m" || die "mktemp failed"
  "$real" --session "$sess" ${target:+--cdp "$target"} "$@" 9>&- & cp=$!
  ( sleep "$t"; : >"$m"; kill -9 "$cp" ) >/dev/null 2>&1 9>&- & wp=$!
  wait "$cp"; rc=$?
  kill "$wp" 2>/dev/null; wait "$wp" 2>/dev/null
  [ -e "$m" ] || return $rc
  rm -f "$m"; stop_daemon; return 124
}
# Fresh daemon before (re)pinning: a live one keeps its old browser whatever --cdp says, and one
# that silently reconnected keeps its old sockets open (each attached to every tab) or is hung.
fresh_daemon() { daemon_pid >/dev/null || return 0; bounded 15 ab close >/dev/null 2>&1; stop_daemon; }

# Run agent-browser (output redacted); when a pinned session fails on its connection, say so loudly.
run() {
  out=$(mktemp "${TMPDIR:-/tmp}/ab-guard.XXXXXX") && err=$(mktemp "${TMPDIR:-/tmp}/ab-guard.XXXXXX") || die "mktemp failed"
  bounded "${limit:-0}" ab "$@" >"$out" 2>"$err"; rc=$?
  redact <"$out"; redact <"$err" >&2
  [ $rc -eq 124 ] && echo "agent-browser: no answer from the browser within ${limit}s; stopped this session's daemon." | tee "$err" >&2
  if [ $rc -ne 0 ] && [ -n "$target" ] && grep -qiE 'cdp|websocket|connect|closed|timed out|no answer' "$err"; then
    echo "agent-browser: lost the $(kind "$target") browser this session is connected to. NOT falling back to a local browser. Re-run your \`agent-browser connect '...'\` command, then \`agent-browser whoami\`." >&2
  fi
  rm -f "$out" "$err"
  return $rc
}

whoami_() {
  if [ -z "$target" ] && ! "$real" session list 2>/dev/null | awk -v s="$sess" '$NF==s{f=1} END{exit !f}'; then
    echo "session=$sess browser=none: run \`agent-browser connect '<url>'\` first"; return 1
  fi
  live=$(bounded 20 ab get cdp-url 2>&1) || {
    echo "session=$sess browser=$(kind "$target") state=DISCONNECTED: $(printf '%s' "$live" | tail -n 1 | redact)"
    echo "ERROR: re-run your \`agent-browser connect '...'\` command"; return 1
  }
  probe=$(bounded 20 ab eval '"ID|" + [navigator.userAgent, navigator.webdriver, innerWidth + "x" + innerHeight].join("|")' 2>&1)
  probe=${probe#\"}; probe=${probe%\"}
  case $probe in
    ID\|*\|*\|*) ;;
    *) echo "session=$sess browser=$(kind "$target") state=UNVERIFIED: $(printf '%s' "$probe" | tail -n 1 | redact)"
       echo "ERROR: could not read the page's identity; re-run your \`agent-browser connect '...'\` command"; return 1;;
  esac
  rest=${probe#ID|}; ua=${rest%%|*}; rest=${rest#*|}; wd=${rest%%|*}; vp=${rest#*|}
  url=$(bounded 20 ab get url 2>/dev/null)
  case $ua in *HeadlessChrome*) headless=yes;; *) headless=no;; esac
  match=yes
  case $target in
    '') ;;
    ws://*|wss://*) [ "$live" = "$target" ] || match=no;;
    *[!0-9]*) hp=${target#*://}; hp=${hp%%/*}; case $live in *"//$hp"[:/]*) ;; *) match=no;; esac;;
    *) case $live in *":$target/"*) ;; *) match=no;; esac;;
  esac
  k=$(kind "$target")
  echo "session=$sess browser=$k match=$match headless=$headless webdriver=$wd viewport=$vp"
  echo "ua=$ua"
  printf 'url=%s\ncdp=%s\n' "$url" "$live" | redact
  if [ $match = no ]; then echo "ERROR: driving a different browser than this session connected to. Re-run connect."; return 1; fi
  case $k$headless in
    extensionyes|embeddedyes) echo "ERROR: headless browser where the user's browser was expected. Re-run connect."; return 1;;
    local*) echo "NOTE: agent-browser's own Chrome; the user cannot see it.";;
  esac
}

# Switch the pin to $1 (from none, too: an unpinned daemon may be driving a local Chrome).
retarget() { [ "$target" = "$1" ] && return; fresh_daemon; save "$1"; }

# One session command at a time (flock where available): a reconnect or close must never
# interleave with another call's read of the pin. Spawned agent-browser processes close fd 9.
if command -v flock >/dev/null; then
  mkdir -p "$pin_dir" && exec 9>"$pin_dir/$sess.lock" && flock -w 180 9 || die "session '$sess' is busy; retry"
  target=$(cat "$pin" 2>/dev/null)
fi

[ -n "$flag_cdp" ] && [ -n "$other" ] && exec "$real" "$@" 9>&-   # agent-browser rejects --cdp with --auto-connect/-p itself
case $cmd in
  whoami) whoami_; exit;;
  connect)
    [ -n "$arg1" ] || exec "$real" "$@" 9>&-
    [ -z "$flag_cdp" ] || [ "$flag_cdp" = "$arg1" ] || die "--cdp '$(printf %s "$flag_cdp" | redact)' and connect '$(printf %s "$arg1" | redact)' name different browsers"
    fresh_daemon
    save "$arg1"   # pinned BEFORE connecting: a failed connect must not leave the session free to launch locally
    limit=${AGENT_BROWSER_CONNECT_TIMEOUT:-60} run "$@" || exit
    whoami_; exit;;
  close|quit|exit)
    [ -n "$other$all" ] && exec "$real" "$@" 9>&-
    [ -n "$flag_cdp" ] && retarget "$flag_cdp"
    run "$@" && rm -f "$pin"
    exit;;
esac
[ -n "$other" ] && exec "$real" "$@" 9>&-   # explicit --auto-connect / provider: caller chose another browser
[ -n "$flag_cdp" ] && retarget "$flag_cdp"
if [ -n "$target" ]; then run "$@"; exit; fi
exec "$real" "$@" 9>&-
