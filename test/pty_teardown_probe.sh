#!/bin/bash
# Probe: does the bridge's one-shot RUN teardown kill deliberately-backgrounded
# children? Reproduces run_finish()'s exact sequence (SIGKILL the PTY shell,
# then close the master fd) via /tmp/ptykill, and checks which background
# spawn styles survive it.
#
# Usage: bash pty_teardown_probe.sh
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD="$DIR/../build"
PROBE="$BUILD/ptykill"
MARK="$(mktemp -d)"

# Build into build/, not /tmp: a WSL distro that shuts down between invocations
# wipes /tmp, and a missing binary silently reads as "everything was KILLED" —
# exactly the false negative this probe exists to rule out. `run` therefore
# also aborts if the probe cannot execute.
mkdir -p "$BUILD"
gcc -o "$PROBE" "$DIR/pty_teardown_probe.c" -lutil || exit 1

run() {
  local name="$1" cmd="$2"
  "$PROBE" "$cmd" || { echo "  probe FAILED for $name"; exit 1; }
  echo "  spawned: $name"
}

echo "== running four background styles through the teardown =="
run plain  "(sleep 6; echo done > $MARK/plain) &"
run stdout "(sleep 6; echo hello; echo done > $MARK/stdout) &"
run nohup  "nohup sh -c 'sleep 6; echo done > $MARK/nohup' >/dev/null 2>&1 &"
run setsid "setsid sh -c 'sleep 6; echo done > $MARK/setsid' >/dev/null 2>&1 &"

# Control: a FOREGROUND child must not survive. Without it, a probe that fails
# to spawn anything at all reads as "everything was killed" and looks like a
# confirmed bug.
run fg "sleep 6; echo done > $MARK/fg"

echo "teardown done; waiting for the 6s sleeps to elapse..."
sleep 9

echo "== results (expected: fg KILLED, all others SURVIVED) =="
for v in plain stdout nohup setsid fg; do
  if [ -f "$MARK/$v" ]; then
    echo "$v: SURVIVED"
  else
    echo "$v: KILLED"
  fi
done
rm -rf "$MARK"
